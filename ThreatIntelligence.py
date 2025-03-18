import shutil
import os
import json

from stix2 import MemoryStore, parse, Filter
from git import Repo # GitPython module
from neo4j import GraphDatabase
from OTXv2 import OTXv2
from dotenv import find_dotenv, load_dotenv

def reset_permissions(path):
    # Generates list of directories, subdirectories, and files starting from the specified path
    for root, dirs, files in os.walk(path):
        for name in files:
            os.chmod(os.path.join(root, name), 0o777)
        for name in dirs:
            os.chmod(os.path.join(root, name), 0o777)

# Function to create or update threat group nodes
def store_threat_groups(driver, threat_groups):
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
        print("All data has been deleted from the database.")
        
        for group in threat_groups:
            session.run(
                """
                MERGE (tg:ThreatGroup {name: $name})
                SET tg.description = $description
                WITH tg
                UNWIND $aliases AS alias
                MERGE (a:Alias {name: alias})
                MERGE (tg)-[:HAS_ALIAS]->(a)
                """,
                name=group.get("name", "Unknown"),
                description=group.get("description", "No description available."),
                aliases=group.get("aliases", [])
            )

def store_pulses(driver, group_name, pulses, OTX_API_KEY):
    """
    Display the pulse data in a readable format.
    """
    # Check if 'results' key exists in the response
    if 'results' in pulses and isinstance(pulses['results'], list):
        if len(pulses['results']) != 0:            
            for pulse in pulses['results']:
                # Access pulse details safely
                pulse_id = pulse.get('id', 'N/A')
                pulse_name = pulse.get('name', 'N/A')
                pulse_created = pulse.get('created', 'N/A')
                pulse_description = pulse.get('description', 'No description available.')
                pulse_malware_families = pulse.get('malware_families', 'N/A')
                pulse_targeted_countries = pulse.get('targeted_countries', 'N/A')
                pulse_industries = pulse.get('industries', 'N/A')
                
                with driver.session() as session:
                    # Create or update the Pulse node with additional properties
                    query_pulse = (
                        "MERGE (p:Pulse {name: $pulse_name, group: $group_name}) "
                        "ON CREATE SET p.createdBy = $group_name, "
                        "               p.id = $pulse_id, "
                        "               p.description = $pulse_description, "
                        "               p.created = $pulse_created, "
                        "               p.malware_families = $pulse_malware_families, "
                        "               p.targeted_countries = $pulse_targeted_countries, "
                        "               p.industries = $pulse_industries "
                        "ON MATCH SET p.group = COALESCE(p.group, $group_name), "
                        "               p.description = $pulse_description, "
                        "               p.created = $pulse_created, "
                        "               p.malware_families = $pulse_malware_families, "
                        "               p.targeted_countries = $pulse_targeted_countries, "
                        "               p.industries = $pulse_industries"
                    )
                    session.run(query_pulse, {
                        "pulse_name": pulse_name,
                        "group_name": group_name,
                        "pulse_id": pulse_id,
                        "pulse_description": pulse_description,
                        "pulse_created": pulse_created,
                        "pulse_malware_families": pulse_malware_families,
                        "pulse_targeted_countries": pulse_targeted_countries,
                        "pulse_industries": pulse_industries,
                    })

                    # Link ThreatGroup -> Pulse
                    query_pulse_link = (
                        "MATCH (tg:ThreatGroup {name: $group_name}), (p:Pulse {name: $pulse_name, group: $group_name}) "
                        "MERGE (tg)-[:RELATED_TO]->(p)"
                    )
                    session.run(query_pulse_link, {
                        "group_name": group_name,
                        "pulse_name": pulse_name
                    })
    else:
        print("Invalid response format.")

def fetch_pulsedive_info(driver, group_name):
    # Load the JSON file
    with open('PulsediveInfo.json', 'r') as file:
        data = json.load(file)  # Load the JSON into a Python object
    
    # Ensure it's a list of records
    if isinstance(data, list):
        # Iterate over each record
        for record in data:
            # Extract the necessary fields
            name = record.get("threat")
            othernames = record.get("othernames", [])
            othernames = [name.lower() for name in othernames]

            if name.lower() == group_name.lower() or group_name.lower() in othernames:
                related_entities = record.get("related", [])
                attributes = record.get("attributes", {})
                ttps = record.get("ttps", {})

                if not isinstance(attributes, dict):
                    continue
                else:
                    country_codes = attributes.get("countrycode", [])

                # Store data inside the database
                store_pulsedive_info(driver, group_name, related_entities, country_codes, ttps)

def store_pulsedive_info(driver, group_name, related, country, ttps):
    with driver.session() as session:
        # Store country codes
        if len(country) > 0:
            query = "MERGE (c:Country {code: $code})"
            session.run(query, {"code": country[0]})

            # Link country codes to threat group
            query_link_country = (
                "MATCH (tg:ThreatGroup {name: $group_name}), (c:Country {code: $code}) "
                "MERGE (tg)-[:ORIGINATES_FROM]->(c)"
            )
            session.run(query_link_country, {
                "group_name": group_name,
                "code": country[0]
            })
        
        # Store related entities (tools, malware, campaigns, etc.)
        for entity in related:
            query = (
                "MERGE (re:RelatedEntity {tid: $tid, name: $name, category: $category, risk: $risk})"
            )
            session.run(query, {
                "tid": entity["tid"],
                "name": entity["name"],
                "category": entity["category"],
                "risk": entity["risk"],
            })

            # Link entities to threat group
            query_link_entity = (
                "MATCH (tg:ThreatGroup {name: $group_name}), (re:RelatedEntity {tid: $tid}) "
                "MERGE (tg)-[:USES]->(re)"
            )
            session.run(query_link_entity, {
                "group_name": group_name,
                "tid": entity["tid"]
            })

        # Store TTPs
        for tactic_name, technique_list in ttps.items():
            # Create a unique tactic node for each group
            query_tactic = (
                "MERGE (t:Tactic {name: $name, group: $group_name}) "
                "ON CREATE SET t.createdBy = $group_name "
                "ON MATCH SET t.group = COALESCE(t.group, $group_name)"
            )
            session.run(query_tactic, {"name": tactic_name, "group_name": group_name})
    
            # Link ThreatGroup -> Tactic
            query_tactic_link = (
                "MATCH (tg:ThreatGroup {name: $group_name}), (t:Tactic {name: $tactic_name, group: $group_name}) "
                "MERGE (tg)-[:USES]->(t)"
            )
            session.run(query_tactic_link, {
                "group_name": group_name,
                "tactic_name": tactic_name
            })

            # Ensure technique_list is valid
            if isinstance(technique_list, list) and technique_list:
                for technique in technique_list:
                    # Create unique techniques for each group's tactics
                    query_technique = (
                        "MERGE (tech:Technique {name: $name, group: $group_name}) "
                        "ON CREATE SET tech.createdBy = $group_name "
                        "ON MATCH SET tech.group = COALESCE(tech.group, $group_name)"
                    )
                    session.run(query_technique, {"name": technique, "group_name": group_name})

                    # Link Tactic -> Technique
                    query_tactic_technique_link = (
                        "MATCH (t:Tactic {name: $tactic_name, group: $group_name}), (tech:Technique {name: $technique_name, group: $group_name}) "
                        "MERGE (t)-[:USES]->(tech)"
                    )
                    session.run(query_tactic_technique_link, {
                        "tactic_name": tactic_name,
                        "technique_name": technique,
                        "group_name": group_name
                    })

def download_repo():
    # Path to the 'cti' directory
    cti_path = 'c:/Users/Rumaan/Documents/SCC Work/SCC300/cti'

    # Allow the deletion of cti directory
    reset_permissions(cti_path)

    # Check if the 'cti' directory exists and delete if it does
    if os.path.exists(cti_path):
        shutil.rmtree(cti_path)

    # Update Git Repo to latest version
    Repo.clone_from("https://github.com/mitre-attack/attack-stix-data.git", "cti")

def fetch_pulses(group_name):
    # Find .env file automatically
    dotenv_path = find_dotenv()

    # Load entries as environent variables
    load_dotenv(dotenv_path)

    OTX_API_KEY = os.getenv("OTX_API_KEY")

    # Initialize the OTX API
    otx = OTXv2(OTX_API_KEY)

    pulses = otx.search_pulses(group_name)
    
    return pulses    
    
def store_threat_group_data():
    # Find .env file automatically
    dotenv_path = find_dotenv()

    # Load entries as environent variables
    load_dotenv(dotenv_path)

    # Store URI and Database Credentials
    URI = "bolt://localhost:7687"
    DB_USER = os.getenv("DB_USER")
    DB_PASS = os.getenv("DB_PASS")
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    AUTH = (DB_USER, DB_PASS)

    # Connect to Database
    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        driver.verify_connectivity()
        print("Successfully Connected")
        store_threat_groups(driver, threat_groups,)
        print("Threat groups successfully stored in Neo4j!")

        alreadyAccessed = {}

        for group in threat_groups:
            group_name = group.get("name", "Unknown")

            if group_name in alreadyAccessed:
                continue

            alreadyAccessed[group_name] = True
            fetch_pulsedive_info(driver, group_name)

            pulses = fetch_pulses(group_name)
            store_pulses(driver, group_name, pulses, OTX_API_KEY)

            print(f"Added all data for {group_name}")

        driver.close()
        print("Connection Closed")

if __name__ == "__main__":
    # download_repo()

    # Load Enterprise ATT&CK data
    with open('cti/enterprise-attack/enterprise-attack.json', 'r') as f:
        enterprise_data = parse(f.read(), allow_custom=True)

    # Create an in-memory store
    ms = MemoryStore()
    ms.add(enterprise_data)

    # Retrieve all intrusion sets (threat groups)
    filter_obj = Filter('type', '=', 'intrusion-set')
    threat_groups = ms.query(filter_obj)

    store_threat_group_data()