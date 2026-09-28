import requests
import logging
import config

logger = logging.getLogger(__name__)

HEADERS = {
    "Authorization": f"Bearer {config.OPENCTI_TOKEN}",
    "Content-Type": "application/json"
}


def _graphql(query: str, variables: dict = None) -> dict:
    """Execute a GraphQL query against OpenCTI."""
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = requests.post(
        f"{config.OPENCTI_URL}/graphql",
        json=payload,
        headers=HEADERS,
        timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def get_recent_reports(limit: int = 10) -> list:
    """Returns the most recently created reports in OpenCTI."""
    query = """
    query GetRecentReports($limit: Int) {
        reports(first: $limit, orderBy: created_at, orderMode: desc) {
            edges {
                node {
                    id
                    name
                    created_at
                    description
                }
            }
        }
    }
    """
    try:
        result = _graphql(query, {"limit": limit})
        edges = result["data"]["reports"]["edges"]
        return [
            {
                "id": e["node"]["id"],
                "name": e["node"]["name"],
                "created_at": e["node"]["created_at"],
                "description": e["node"].get("description", "")
            }
            for e in edges
        ]
    except Exception as e:
        logger.error(f"OpenCTI report fetch failed: {e}")
        return []


def get_observable_count() -> int:
    """Returns total number of observables (IOCs) in OpenCTI."""
    query = """
    query {
        stixCyberObservables {
            pageInfo {
                globalCount
            }
        }
    }
    """
    try:
        result = _graphql(query)
        return result["data"]["stixCyberObservables"]["pageInfo"]["globalCount"]
    except Exception as e:
        logger.error(f"OpenCTI observable count failed: {e}")
        return 0
