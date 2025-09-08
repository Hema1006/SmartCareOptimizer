# ml_pipeline.py

import pandas as pd
from geopy.distance import great_circle

# --- Constants for ML Calculations ---
coverage_map = {"PPO": 0.85, "HMO": 0.75, "EPO": 0.65}
visits_map = {"Low": 2, "Medium": 5, "High": 10}


# --- Core ML & Logic Functions ---

def find_providers_in_radius(member_lat, member_lon, providers_df,
                             max_minutes=30, avg_speeds=(30, 35, 40)):
    """Finds providers within a certain drive time by testing different average speeds."""
    for speed in avg_speeds:
        max_miles = (speed * max_minutes) / 60
        providers_in_radius = []
        for _, provider in providers_df.iterrows():
            dist = great_circle((member_lat, member_lon),
                                (provider['latitude'], provider['longitude'])).miles
            if dist <= max_miles:
                provider_data = provider.to_dict()
                provider_data['distance_miles'] = round(dist, 2)
                provider_data['drive_time_minutes'] = round((dist / speed) * 60, 1)
                providers_in_radius.append(provider_data)
        if providers_in_radius:
            df = pd.DataFrame(providers_in_radius)
            df.loc[:, "avg_speed_used"] = speed
            return df
    return pd.DataFrame()


def filter_providers_by_specialization(providers_df, primary_need=None, secondary_need=None):
    """Filters providers based on member's primary and secondary specialty needs."""
    if (not primary_need or primary_need == 'None') and (not secondary_need or secondary_need == 'None'):
        return providers_df[(providers_df['specialty'] == 'General Practice') | (
                providers_df['secondary_specialty'] == 'General Practice')]
    else:
        needs = {primary_need, secondary_need} - {None, 'None'}
        return providers_df[(providers_df['specialty'].isin(needs)) | (providers_df['secondary_specialty'].isin(needs))]


def calculate_quality_score(row):
    """Calculates a weighted quality score for a provider based on multiple factors."""
    score, total_weight = 0.0, 0.0
    exp_score = min(row.get("experience_years", 0) / 40, 1) * 10
    score += exp_score * 0.20;
    total_weight += 0.20
    rating_score = (row.get("patient_rating") / 5) * 10
    score += rating_score * 0.20;
    total_weight += 0.20
    cms_score = (row.get("CMS_quality_score") / 5) * 10
    score += cms_score * 0.25;
    total_weight += 0.25
    risk = row.get("risk_rate", 0.2)
    risk_score = (1 - max(0, min(1, risk))) * 10
    score += risk_score * 0.15;
    total_weight += 0.15
    cert_score = 0
    if bool(row.get("certified", True)): cert_score += 5
    if bool(row.get("background_check_passed", True)): cert_score += 5
    score += cert_score * 0.10;
    total_weight += 0.10
    tele_score = 10 if bool(row.get("telehealth_available", False)) else 0
    score += tele_score * 0.10;
    total_weight += 0.10
    return max(1, min(10, score / total_weight)) if total_weight > 0 else 5


def apply_quality_filter(df, min_threshold=6.0):
    """Applies the quality score calculation and filters out providers below a threshold."""
    if df.empty: return df
    df = df.copy()
    df["quality_score"] = df.apply(calculate_quality_score, axis=1).round(1)
    return df[df["quality_score"] >= min_threshold]


def _negotiated_rate(row):
    """Calculates a provider's negotiated service rate based on experience and quality."""
    base = float(row.get("service_cost", 0))
    exp = float(row.get("experience_years", 0))
    quality = float(row.get("CMS_quality_score", 3))
    exp_factor = 1 + 0.002 * min(max(exp, 0), 40)
    quality_factor = 1 - 0.02 * (quality - 3)
    return base * exp_factor * quality_factor


def calculate_payments_row(row, member):
    """Calculates the expected insurer and member payments for a given provider and member."""
    rate = _negotiated_rate(row)
    visits = visits_map.get(member.get("risk_level", "Medium"), 5)
    coverage_share = coverage_map.get(member.get("coverage_plan", "HMO"), 0.75)
    insurer_payment = rate * coverage_share * visits
    member_share = rate * (1 - coverage_share) * visits
    return insurer_payment, member_share, visits, rate


def get_top_providers_for_member(member, providers_df, top_n=3):
    """
    Main pipeline function to get the top N recommended providers for a member.
    This orchestrates all the filtering and scoring steps.
    """
    candidate_providers = providers_df.copy()
    specialized = filter_providers_by_specialization(candidate_providers, member.get('primary_specialty_needed'),
                                                     member.get('secondary_specialty_needed'))
    if specialized.empty: return pd.DataFrame()

    geo_df = find_providers_in_radius(member['latitude'], member['longitude'], specialized)
    if geo_df.empty: return pd.DataFrame()

    quality_df = apply_quality_filter(geo_df, min_threshold=6.0)

    final_list = pd.DataFrame()
    if len(quality_df) >= top_n:
        final_list = quality_df.sort_values(by=['quality_score', 'distance_miles'], ascending=[False, True]).head(top_n)
    else:
        # If not enough high-quality providers, fall back to the closest ones
        final_list = geo_df.sort_values(by=['distance_miles']).head(top_n)

    if final_list.empty: return pd.DataFrame()

    # Calculate final costs and other metrics for the recommended list
    final_list = final_list.copy()
    payments = final_list.apply(lambda r: calculate_payments_row(r, member), axis=1)
    final_list.loc[:, "insurance_payment"] = [p[0] for p in payments]
    final_list.loc[:, "member_share"] = [p[1] for p in payments]
    final_list.loc[:, "expected_visits"] = [p[2] for p in payments]
    final_list.loc[:, "negotiated_rate"] = [p[3] for p in payments]

    # Ensure quality score is present if it wasn't calculated in the fallback step
    if "quality_score" not in final_list.columns:
        final_list["quality_score"] = final_list.apply(calculate_quality_score, axis=1).round(1)

    return final_list.reset_index(drop=True)
