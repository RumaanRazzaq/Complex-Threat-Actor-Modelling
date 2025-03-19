import shutil
import os
import json

from stix2 import MemoryStore, parse, Filter
from git import Repo # GitPython module
from neo4j import GraphDatabase
from OTXv2 import OTXv2
from dotenv import find_dotenv, load_dotenv

def reset_permissions(path):
    """
    Recursively sets permissions to 777 for all files and directories starting from the specified path.
    This makes all files and directories readable, writable, and executable by everyone - only used for this folder specifically to clear the outdated Github Repo
    """
    for root, dirs, files in os.walk(path):
        for name in files:
            os.chmod(os.path.join(root, name), 0o777)
        for name in dirs:
            os.chmod(os.path.join(root, name), 0o777)

def store_threat_groups(driver, threat_groups):
    """
    Creates or updates threat group nodes in a Neo4j database. Deletes all existing data before inserting new threat groups.
    
    Parameters:
    - driver: Neo4j database driver instance.
    - threat_groups: List of dictionaries containing threat group data - taken from MITRE Github repo.
    """
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

def store_pulses(driver, group_name, pulses):
    """
    Stores pulse data in a Neo4j database and links it to threat groups.
    
    Parameters:
    - driver: Neo4j database driver instance.
    - group_name: Name of the threat group being stored.
    - pulses: Dictionary containing pulse data from PulsediveInfo.json
    """
    # Check if 'results' key exists and contains a valid list and loops through the pulses
    if 'results' in pulses and isinstance(pulses['results'], list):
        if len(pulses['results']) != 0:            
            for pulse in pulses['results']:
                # Accesses the pulse details safely - setting to N/A if variable not found
                pulse_id = pulse.get('id', 'N/A')
                pulse_name = pulse.get('name', 'N/A')
                pulse_created = pulse.get('created', 'N/A')
                pulse_description = pulse.get('description', 'No description available.')
                pulse_malware_families = pulse.get('malware_families', 'N/A')
                pulse_targeted_countries = pulse.get('targeted_countries', 'N/A')
                pulse_industries = pulse.get('industries', 'N/A')
                
                with driver.session() as session:
                    # Create the Pulse node with additional properties
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
    """
    Fetches Pulsedive threat intelligence information and stores relevant details. It starts by loading the JSON file containing Pulsedive threat intelligence data
    We then ensure it is a list of records and iterate over each record. The necessary fields are extracted. 
    The threat group's name checks if it matches the given group name. The extracted data is then stored into the database.

    Parameters:
    - driver: Neo4j database driver instance.
    - group_name: Name of the threat group to match in the Pulsedive data.
    """

    with open('PulsediveInfo.json', 'r') as file:
        data = json.load(file)
    
    if isinstance(data, list):
        for record in data:
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

                store_pulsedive_info(driver, group_name, related_entities, country_codes, ttps)

def store_pulsedive_info(driver, group_name, related, country, ttps):
    """
    Stores Pulsedive threat intelligence information into a Neo4j database. 
    This includes linking threat groups to country codes, related entities, and TTPs (tactics, techniques, and procedures).

    Parameters:
    - driver: Neo4j database driver instance.
    - group_name: Name of the threat group.
    - related: List of related entities (tools, malware, campaigns, etc.).
    - country: List of country codes associated with the threat group.
    - ttps: Dictionary containing tactics as keys and their respective techniques as values.
    """
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
    """
    Clones the MITRE ATT&CK STIX data repository into the local 'cti' directory. 
    If the directory already exists, it resets permissions and deletes it before downloading the latest version.
    """

    cti_path = 'c:/Users/Rumaan/Documents/SCC Work/SCC300/cti'
    reset_permissions(cti_path)

    if os.path.exists(cti_path):
        shutil.rmtree(cti_path)

    Repo.clone_from("https://github.com/mitre-attack/attack-stix-data.git", "cti")

def fetch_pulses(group_name):
    """
    Automatically locates and load the .env file. The OTX API key is retrieved from the environment variables.
    We then initialize the OTX API client and query the API for pulses related to the given group name. The fetched pulses are returned.
    
    Parameters:
    - group_name: Name of the threat group to search for in OTX pulses.
    
    Returns:
    - pulses: JSON response containing relevant threat intelligence pulses.
    """

    dotenv_path = find_dotenv()
    load_dotenv(dotenv_path)
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    otx = OTXv2(OTX_API_KEY)
    pulses = otx.search_pulses(group_name)
    return pulses    
    
def store_threat_group_data():
    """
    Loads environment variables from the .env file and retrieves database credentials and API keys.
    We then establish a connection to the Neo4j database and stores threat group data.
    Additional data is fetched from Pulsedive and AlienVault OTX and stored into the database.
    """

    dotenv_path = find_dotenv()
    load_dotenv(dotenv_path)
    URI = "bolt://localhost:7687"
    DB_USER = os.getenv("DB_USER")
    DB_PASS = os.getenv("DB_PASS")
    OTX_API_KEY = os.getenv("OTX_API_KEY")
    AUTH = (DB_USER, DB_PASS)

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