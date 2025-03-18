from neo4j import GraphDatabase
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import scipy.stats as stats
from dotenv import find_dotenv, load_dotenv
from sklearn.metrics import r2_score
from scipy.stats import pearsonr
from sklearn.linear_model import LinearRegression
from datetime import datetime, timedelta
import statsmodels.api as sm

def get_threat_group_data(driver):
    query = """
        MATCH (tg:ThreatGroup)
        OPTIONAL MATCH (tg)-[:USES]->(ttp:Tactic)-[:USES]->(t:Technique)
        WITH tg, COUNT(t) AS ttp_count
        OPTIONAL MATCH (tg)-[:RELATED_TO]->(p:Pulse)
        WITH tg, ttp_count, COUNT(p) AS pulse_count,
               AVG(datetime().epochSeconds - datetime(p.created).epochSeconds) / 86400 AS pulse_age_days
        OPTIONAL MATCH (tg)-[:USES]->(re:RelatedEntity)
        WITH tg, ttp_count, pulse_count, pulse_age_days, COUNT(re) AS all_related_entities
        OPTIONAL MATCH (tg)-[:USES]->(re_tool:RelatedEntity)
        WHERE re_tool.category = 'tool'
        WITH tg, ttp_count, pulse_count, pulse_age_days, all_related_entities, COUNT(re_tool) AS tool_related_entities
        OPTIONAL MATCH (tg)-[:USES]->(re_malware:RelatedEntity)
        WHERE re_malware.category = 'malware'
        WITH tg, ttp_count, pulse_count, pulse_age_days, all_related_entities, tool_related_entities, 
             COUNT(re_malware) AS malware_related_entities
        OPTIONAL MATCH (tg)-[:HAS_ALIAS]->(a:Alias)
        RETURN tg.name AS threat_group, ttp_count, pulse_count, pulse_age_days, 
               all_related_entities, tool_related_entities, malware_related_entities,
               COUNT(a) AS alias_count
    """
    with driver.session() as session:
        results = session.run(query)
        return results.data()
    
def fetch_pulse_data(driver):
    '''
    Retrieve pulses and their creation timestamps from Neo4j.
    '''

    with driver.session() as session:
        query = """
        MATCH (tg:ThreatGroup)-[:RELATED_TO]->(p:Pulse)
        RETURN tg.name AS threat_group, p.created AS pulse_created
        """
        
        result = session.run(query)
        data = [{"threat_group": record["threat_group"], "pulse_created": record["pulse_created"]} for record in result]
        
        return data

def plot_histograms(df):
    '''
    Plots histograms for:
    - Pulse count
    - TTP count
    - Tool + Malware count (Combined)
    - Pulse age (days)
    - Alias count
    - All related entities count
    - Tool-only related entities count
    - Malware-only related entities count
    '''
    variables = [
        'pulse_count', 'ttp_count', 'pulse_age_days', 'alias_count',
        'all_related_entities', 'tool_related_entities', 'malware_related_entities'
    ]
    
    titles = [
        "Pulse Count", "TTP Count", "Pulse Age (Days)", "Alias Count",
        "All Related Entities", "Tool-Only Related Entities", "Malware-Only Related Entities"
    ]
    
    for var in variables:
        data = df[var].dropna()
        if len(data) > 1:
            median_val = np.median(data)
            iqr_val = iqr(data)
            kurtosis_val = stats.kurtosis(data)

            print(f"\nStatistics for {var}:")
            print(f"Median: {median_val:.2f}")
            print(f"IQR: {iqr_val:.2f}")
            print(f"Kurtosis: {kurtosis_val:.2f}")
        else:
            print(f"\nNot enough data for {var} to compute statistics.")


    fig, axes = plt.subplots(2, 4, figsize=(20, 10))

    for i, var in enumerate(variables):
        ax = axes[i // 4, i % 4] 
        data = df[var].dropna()

        ax.hist(data, bins=20, alpha=0.7, color='b', edgecolor='black', density=True)

        if len(data) > 1:
            mu, std = stats.norm.fit(data)
            xmin, xmax = ax.get_xlim()
            x = np.linspace(xmin, xmax, 100)
            p = stats.norm.pdf(x, mu, std)
            ax.plot(x, p, 'r', linewidth=2)
            ax.set_title(f"{titles[i]}\nFit: μ={mu:.2f}, σ={std:.2f}")
        else:
            ax.set_title(f"{titles[i]}\nNot Enough Data")

        ax.set_xlabel(titles[i])
        ax.set_ylabel("Density")

    plt.tight_layout()
    plt.show()

def plot_malware_vs_techniques(df):
    plt.figure(figsize=(10, 6))
    plt.scatter(df['malware_related_entities'], df['ttp_count'], alpha=0.7, label='Threat Groups')

    X = df[['malware_related_entities']]
    y = df['ttp_count']
    model = LinearRegression()
    model.fit(X, y)
    y_pred = model.predict(X)

    r2 = r2_score(y, y_pred)
    pearson_corr, p_value = pearsonr(df['malware_related_entities'], df['ttp_count'])

    plt.plot(df['malware_related_entities'], y_pred, color='red', linestyle='--', label=f'Best Fit Line (R²={r2:.2f})\nPearson Correlation Coefficient = {pearson_corr:.2f}, P-value = {p_value:.5f}')
    plt.title("Malware Used vs. Techniques Employed per Threat Group")
    plt.xlabel("Number of Malware Used")
    plt.ylabel("Number of Techniques Used")
    plt.legend()
    plt.show()

def plot_malwaretools_vs_techniques(df):
    plt.figure(figsize=(12, 7))

    scatter = plt.scatter(df['all_related_entities'], df['ttp_count'], 
                          s=df['pulse_count'] * 10,
                          c=range(len(df)), cmap='viridis', alpha=0.7, edgecolors='k')

    X = df[['all_related_entities']]
    y = df['ttp_count']
    model = LinearRegression()
    model.fit(X, y)
    y_pred = model.predict(X)

    r2 = r2_score(y, y_pred)
    pearson_corr, p_value = pearsonr(df['all_related_entities'], df['ttp_count'])

    plt.plot(df['all_related_entities'], y_pred, color='red', linestyle='--', label=f'Best Fit Line (R²={r2:.2f})\nPearson Correlation Coefficient = {pearson_corr:.4f}, P-value = {p_value:.2e}')

    for i, txt in enumerate(df['threat_group']):
        if df['ttp_count'][i] > np.percentile(df['ttp_count'], 80) or df['all_related_entities'][i] > np.percentile(df['all_related_entities'], 80):
            plt.annotate(txt, (df['all_related_entities'][i], df['ttp_count'][i]), fontsize=9, alpha=0.8)

    plt.colorbar(scatter, label="Threat Groups")
    plt.title("Threat Group Activity: Tools/Malware vs. TTPs")
    plt.xlabel("Number of Tools/Malware Used")
    plt.ylabel("Number of Tactics & Techniques Used")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.show()

def process_data(df):
    """
    Processes the data for analysis.
    Converts timestamps and identifies inactive/emerging threats.
    Computes PMF for pulse counts per threat group per month.
    """
    df["pulse_created"] = pd.to_datetime(df["pulse_created"], format='%Y-%m-%dT%H:%M:%S.%f', errors='coerce')
    df["pulse_created"].fillna(pd.to_datetime(df["pulse_created"], format='%Y-%m-%dT%H:%M:%S', errors='coerce'), inplace=True)

    df = df.dropna(subset=["pulse_created"])

    # Group data by month
    df["year_month"] = df["pulse_created"].dt.to_period("M")
    df_grouped = df.groupby(["year_month", "threat_group"]).size().reset_index(name="pulse_count")

    df_grouped["year_month"] = df_grouped["year_month"].astype(str)

    # Calculate PMF for pulse counts
    pmf_pulse_counts = df_grouped.groupby(["year_month", "pulse_count"]).size() / df_grouped.groupby("year_month").size()
    pmf_pulse_counts = pmf_pulse_counts.reset_index(name="PMF")

    print("PMF of Pulse Counts per Threat Group per Month:")
    print(pmf_pulse_counts)

    return df_grouped, df


def classify_threats(df):
    """
    Classifies threats as inactive or emerging based on their activity over time.
    
    Returns two lists: inactive threats and emerging threats.
    """

    INACTIVE_THRESHOLD_MONTHS = 90   # No activity in the last 12 months -> inactive
    EMERGING_FIRST_PULSE_LIMIT = 24  # First pulse must be within the last 24 months (2 years)
    EMERGING_RECENT_PULSE_LIMIT = 24 # Must have activity in the last 12 months (1 year)

    current_date = datetime.now()
    inactive_threats = []
    emerging_threats = []

    for threat_group, group_data in df.groupby("threat_group"):
        first_seen = group_data["pulse_created"].min()
        last_seen = group_data["pulse_created"].max()

        if last_seen < (current_date - timedelta(days=INACTIVE_THRESHOLD_MONTHS * 30)):  
            inactive_threats.append(threat_group)

        elif (
            first_seen > (current_date - timedelta(days=EMERGING_FIRST_PULSE_LIMIT * 30)) and
            last_seen > (current_date - timedelta(days=EMERGING_RECENT_PULSE_LIMIT * 30))
        ):
            emerging_threats.append(threat_group)

    return inactive_threats, emerging_threats

def plot_threats(df, threat_list, title):
    """
    Plots threat attribution rate for a given list of threats.
    
    Parameters:
        df (pd.DataFrame): Grouped DataFrame containing time-based pulse counts.
        threat_list (list): List of threats to include in the plot.
        title (str): Title of the figure.
    """
    df_filtered = df[df["threat_group"].isin(threat_list)]

    if df_filtered.empty:
        print(f"No data available for {title} threats.")
        return

    df_pivot = df_filtered.pivot(index="year_month", columns="threat_group", values="pulse_count").fillna(0)

    fig, ax = plt.subplots(figsize=(14, 7))
    df_pivot.plot(kind="line", marker="o", ax=ax)

    ax.set_title(f"Rate of Attribution of {title} Threats Over Time")
    ax.set_xlabel("Time (Month)")
    ax.set_ylabel("Number of Pulses")
    ax.legend(title="Threat Group", bbox_to_anchor=(1.05, 1), loc="upper left")
    ax.grid(True)

    plt.show()

def detect_outliers(df, columns):
    """
    Detects and removes outliers using the IQR method for specified columns.
    
    Parameters:
        df (pd.DataFrame): The input DataFrame.
        columns (list): List of column names to check for outliers.
    
    Returns:
        tuple: A cleaned DataFrame without outliers, and a dictionary of outliers for each column.
    """
    outliers_dict = {} 
    outlier_indices = set()

    for col in columns:
        if not pd.api.types.is_numeric_dtype(df[col]):
            print(f"Skipping non-numeric column: {col}")
            continue

        Q1 = df[col].quantile(0.25)
        Q3 = df[col].quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR

        outliers = df[(df[col] < lower_bound) | (df[col] > upper_bound)]
        if not outliers.empty:
            outliers_dict[col] = outliers
            outlier_indices.update(outliers.index)

    df_clean = df.drop(index=list(outlier_indices))

    return df_clean, outliers_dict

def plot_ols_regression(df):
    df['combined_related_entities'] = df['tool_related_entities'].fillna(0) + df['malware_related_entities'].fillna(0)

    df_clean, outliers = detect_outliers(df, ['combined_related_entities', 'alias_count', 'ttp_count'])
    print(f"Removed {len(outliers)} outliers.")
    
    X = df_clean[['combined_related_entities', 'alias_count']]
    X = sm.add_constant(X) 
    y = df_clean['ttp_count']
    
    model = sm.OLS(y, X).fit()
    predictions = model.predict(X)
    
    print(model.summary())
    
    plt.figure(figsize=(10, 6))
    plt.scatter(y, predictions, alpha=0.7, edgecolors='k')
    plt.plot([y.min(), y.max()], [y.min(), y.max()], '--', color='red')
    plt.xlabel("Actual TTP Count")
    plt.ylabel("Predicted TTP Count")
    plt.title("OLS Regression: Actual vs. Predicted TTP Count")
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.show()

def main():
    """
    Main function to fetch threat group data and plot histograms.
    """
    dotenv_path = find_dotenv()
    load_dotenv(dotenv_path)

    URI = "bolt://localhost:7687"
    DB_USER = os.getenv("DB_USER")
    DB_PASS = os.getenv("DB_PASS")
    AUTH = (DB_USER, DB_PASS)

    with GraphDatabase.driver(URI, auth=AUTH) as driver:
        print("Fetching threat group data from Neo4j...")
        threat_data = get_threat_group_data(driver)
        pulse_data = fetch_pulse_data(driver)
        df = pd.DataFrame(threat_data)

        if df.empty:
            print("No threat group data found!")
            return

        plot_histograms(df)
        plot_malware_vs_techniques(df)
        plot_malwaretools_vs_techniques(df)
        plot_ols_regression(df)

        df = pd.DataFrame(pulse_data)
        
        if df.empty:
            print("No pulse data found!")
            return
        
        df_grouped, df = process_data(df)
        inactive_threats, emerging_threats = classify_threats(df)
        plot_threats(df_grouped, inactive_threats, "Inactive")
        plot_threats(df_grouped, emerging_threats, "Emerging")

if __name__ == "__main__":
    main()