#!/usr/bin/env python3
import requests
import json
import time
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urljoin
from osquery_compliance import load_stig_checks, get_os_type

@dataclass
class CentraConfig:
    management_server: str
    api_port: int = 443
    api_version: str = "v3.0"
    verify_ssl: bool = True

class CentraOSQueryClient:
    def __init__(self, config: CentraConfig):
        self.config = config
        self.base_url = f"https://{config.management_server}:{config.api_port}"
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.token = None


    
    def authenticate(self, sso_token: str = None) -> None:
        """Authenticate with the Centra API using username/password or SSO token.
        
        Args:
            sso_token: Optional SSO token obtained from the web interface. If provided,
                      username/password authentication will be skipped.
        """
        print("\nAuthenticating with Centra API...")
        
        # Set up headers for authentication
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        
        # Check if SSO token is provided
        if sso_token:
            print("Using provided SSO token for authentication")
            self.token = sso_token
            # Add token to session headers
            self.session.headers.update({
                "Authorization": f"Bearer {self.token}"
            })
            
            # Verify the token works by making a test request
            try:
                # Try to access a simple endpoint to verify the token
                test_url = urljoin(self.base_url, "/api/v3.0/system-info")
                response = self.session.get(test_url)
                if response.status_code == 200:
                    print("SSO token authentication successful!")
                    return
                else:
                    print(f"SSO token validation failed: {response.status_code}")
                    print("Falling back to username/password authentication")
            except requests.exceptions.RequestException as e:
                print(f"Error validating SSO token: {str(e)}")
                print("Falling back to username/password authentication")
        
        # If we get here, either no SSO token was provided or it failed validation
        # Get credentials from user
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        # According to the Swagger documentation, the correct authentication endpoint is /api/v3.0/authenticate
        auth_url = urljoin(self.base_url, "/api/v3.0/authenticate")
        auth_data = {
            "username": username,
            "password": password
        }
        print(f"Sending auth request to: {auth_url}")
        
        try:
            # According to Swagger, we should use JSON payload
            print("Attempting authentication with JSON payload...")
            response = self.session.post(auth_url, json=auth_data)
            print(f"Status code: {response.status_code}")
            print(f"Response headers: {response.headers}")
            
            if response.status_code == 200:
                print("Authentication successful!")
            elif len(response.text) < 500:
                print(f"Response text: {response.text}")
            else:
                print("Response too large to display")
                
        except requests.exceptions.RequestException as e:
            print(f"Error with authentication: {str(e)}")
            raise
        
        # If we got here without a successful authentication, use the last response
        try:
            response.raise_for_status()
            
            # Extract token from response
            data = response.json()
            if 'access_token' in data:
                self.token = data['access_token']
            else:
                print("No access token in response:")
                print(data)
                raise Exception("Authentication failed: No access token received")
            
            # Add token to session headers
            self.session.headers.update({
                "Authorization": f"Bearer {self.token}"
            })
            print("Successfully authenticated!")
            
        except requests.exceptions.RequestException as e:
            print(f"Authentication failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None and e.response.text:
                print(f"Response: {e.response.text}")
            raise

    def run_query(self, query: str, filters: Optional[Dict] = None) -> int:
        """Run an osquery query on selected agents.
        
        Args:
            query: The osquery SQL query to run
            filters: Optional filters to select specific agents
            
        Returns:
            query_id: The ID of the executed query for retrieving results
        """
        # Based on the Swagger documentation, the correct endpoint is /api/v3.0/agents/query
        query_url = urljoin(self.base_url, "/api/v3.0/agents/query")
        
        # Prepare query data according to the Swagger API documentation
        # The correct format includes 'action': 'run' and a 'filter' object
        # Using an empty filter to include all agents if no specific filter is provided
        if filters:
            query_data = {
                "action": "run",
                "query": query,
                "filter": filters
            }
        else:
            # Use an empty filter to get all agents
            query_data = {
                "action": "run",
                "query": query,
                "filter": {}
            }
        
        print(f"Sending query request to: {query_url}")
        print(f"Query data: {json.dumps(query_data, indent=2)}")
        
        try:
            # According to Swagger, we should use POST method
            response = self.session.post(query_url, json=query_data)
            print(f"Response status code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"Error response: {response.text}")
                
                # Check specifically for the "no valid agent" error
                if response.status_code == 400 and "Current filters selection does not include any valid agent" in response.text:
                    print("\nERROR: No valid agents found in the system that match the filter criteria.")
                    print("This could be because:")
                    print("1. There are no agents installed or connected")
                    print("2. The agents don't match the filter criteria")
                    print("3. The agents don't have osquery capability")
                    print("\nPlease verify agent installation and connectivity before proceeding.")
                    raise ValueError("No valid agents available for querying")
                    
            response.raise_for_status()
            
            data = response.json()
            print(f"Response data: {json.dumps(data, indent=2)}")
            
            # According to the API docs, the query ID should be returned
            query_id = data.get("query_id") or data.get("id")
            if not query_id:
                raise ValueError(f"No query ID in response: {data}")
            return query_id
            
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response headers: {e.response.headers}")
                print(f"Response body: {e.response.text}")
            raise

    def get_query_status(self, query_id: int) -> Dict:
        """Get the status of a running query."""
        # Based on the Swagger documentation, the correct endpoint is /api/v3.0/agents/query/{query_id}
        status_url = urljoin(self.base_url, f"/api/v3.0/agents/query/{query_id}")
        try:
            response = self.session.get(status_url)
            print(f"Status response code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"Error response: {response.text}")
            response.raise_for_status()
            
            data = response.json()
            print(f"Status data: {json.dumps(data, indent=2)}")
            return data
            
        except requests.exceptions.RequestException as e:
            print(f"Status check failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response headers: {e.response.headers}")
                print(f"Response body: {e.response.text}")
            raise

    def get_query_results(self, query_id: int, offset: int = 0, limit: int = 100) -> Dict:
        """Get results from a completed query."""
        # Based on the Swagger documentation, the correct endpoint is /api/v3.0/agents/query/{query_id}/results
        results_url = urljoin(self.base_url, f"/api/v3.0/agents/query/{query_id}/results")
        params = {"offset": offset, "limit": limit}
        
        try:
            response = self.session.get(results_url, params=params)
            print(f"Results response code: {response.status_code}")
            
            if response.status_code != 200:
                print(f"Error response: {response.text}")
            response.raise_for_status()
            
            data = response.json()
            print(f"Results data: {json.dumps(data, indent=2)}")
            
        except requests.exceptions.RequestException as e:
            print(f"Results retrieval failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response headers: {e.response.headers}")
                print(f"Response body: {e.response.text}")
            raise
        
        # Transform the results into the expected format
        results = []
        for agent_result in data.get("results", []):
            if agent_result.get("status") == "success":
                results.extend(agent_result.get("rows", []))
        return {"data": results}

    def wait_for_query_completion(self, query_id: int, timeout: int = 300, poll_interval: int = 5) -> bool:
        """Wait for a query to complete, with timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_query_status(query_id)
            query_status = status.get("query_status", {})
            state = query_status.get("state")
            if state in ["completed", "failed", "error"]:
                if state == "completed":
                    success_count = query_status.get("success_count", 0)
                    total_count = query_status.get("total_count", 0)
                    return success_count > 0 and success_count == total_count
                return False
            time.sleep(poll_interval)
        raise TimeoutError(f"Query {query_id} did not complete within {timeout} seconds")

class ComplianceCheck:
    def __init__(self, name: str, description: str, query: str, expected_result: Optional[Dict] = None):
        self.name = name
        self.description = description
        self.query = query
        self.expected_result = expected_result

    def evaluate_result(self, result: Dict) -> bool:
        """Evaluate if a result meets compliance requirements."""
        if not self.expected_result:
            # If no expected result defined, just check if we got any results
            return bool(result.get("data", []))
        
        # Implement specific compliance checking logic here
        # This is a simple example - extend based on your needs
        actual_data = result.get("data", [])
        for row in actual_data:
            if all(row.get(k) == v for k, v in self.expected_result.items()):
                return True
        return False

def batch_queries(checks: List[ComplianceCheck], max_batch_size: int = 5) -> List[Dict]:
    """Combine multiple queries into batches to reduce API calls.
    
    Args:
        checks: List of compliance checks to batch
        max_batch_size: Maximum number of queries to combine in a single batch
        
    Returns:
        List of batched query dictionaries with metadata
    """
    batches = []
    current_batch = []
    current_batch_size = 0
    
    for check in checks:
        # Skip checks that are too complex or have special requirements
        if "JOIN" in check.query.upper() or "WITH" in check.query.upper():
            # These queries might be too complex to combine
            batches.append({
                "checks": [check],
                "query": check.query,
                "is_batch": False
            })
            continue
            
        # Add to current batch if there's room
        if current_batch_size < max_batch_size:
            current_batch.append(check)
            current_batch_size += 1
        else:
            # Create combined query for the current batch
            combined_query = create_combined_query(current_batch)
            batches.append({
                "checks": current_batch,
                "query": combined_query,
                "is_batch": True
            })
            # Start a new batch with this check
            current_batch = [check]
            current_batch_size = 1
    
    # Don't forget the last batch if it has any checks
    if current_batch:
        combined_query = create_combined_query(current_batch)
        batches.append({
            "checks": current_batch,
            "query": combined_query,
            "is_batch": True
        })
    
    return batches

def create_combined_query(checks: List[ComplianceCheck]) -> str:
    """Create a combined SQL query from multiple checks.
    
    Args:
        checks: List of compliance checks to combine
        
    Returns:
        A single SQL query that combines all the individual queries
    """
    if not checks:
        return ""
        
    if len(checks) == 1:
        return checks[0].query
        
    # Add a query identifier to each query so we can determine which results belong to which check
    combined_parts = []
    for i, check in enumerate(checks):
        # Extract the SELECT part and add a constant to identify this query
        # This assumes the query starts with SELECT
        query = check.query.strip()
        if query.upper().startswith("SELECT"):
            # Add a check_id column to identify which check this result belongs to
            query_with_id = query.replace("SELECT", f"SELECT '{check.name}' AS check_id,", 1)
            combined_parts.append(query_with_id)
    
    # Combine with UNION ALL
    return " UNION ALL ".join(combined_parts)

def process_batch_results(batch: Dict, results: Dict) -> Dict[str, Dict]:
    """Process results from a batched query and separate them by check.
    
    Args:
        batch: The batch information including checks and query
        results: The results from the batched query
        
    Returns:
        Dictionary mapping check names to their results
    """
    processed_results = {}
    
    if not batch["is_batch"] or len(batch["checks"]) == 1:
        # This was a single check, just evaluate it directly
        check = batch["checks"][0]
        is_compliant = check.evaluate_result(results)
        processed_results[check.name] = {
            "compliant": is_compliant,
            "description": check.description,
            "results": results
        }
        return processed_results
    
    # For batched queries, we need to separate the results by check_id
    data = results.get("data", [])
    for check in batch["checks"]:
        # Filter results for this specific check
        check_results = {
            "data": [row for row in data if row.get("check_id") == check.name],
            "metadata": results.get("metadata", {})
        }
        
        # Remove the check_id column from each row as it was only for internal use
        for row in check_results["data"]:
            if "check_id" in row:
                del row["check_id"]
        
        # Evaluate compliance for this check
        is_compliant = check.evaluate_result(check_results)
        processed_results[check.name] = {
            "compliant": is_compliant,
            "description": check.description,
            "results": check_results
        }
    
    return processed_results

def run_compliance_checks(client: CentraOSQueryClient, checks: List[ComplianceCheck], 
                        filters: Optional[Dict] = None, batch_size: int = 5) -> Dict[str, Dict]:
    """Run a set of compliance checks and return results.
    
    Args:
        client: The CentraOSQueryClient instance to use for queries
        checks: List of compliance checks to run
        filters: Optional filters to select specific agents
        batch_size: Maximum number of queries to combine in a single batch
        
    Returns:
        Dictionary mapping check names to their results
    """
    results = {}
    
    # Batch the queries to reduce API calls
    batches = batch_queries(checks, batch_size)
    print(f"Batched {len(checks)} checks into {len(batches)} API calls")
    
    for i, batch in enumerate(batches):
        batch_desc = f"Batch {i+1}/{len(batches)}"
        if batch["is_batch"]:
            check_names = [check.name for check in batch["checks"]]
            print(f"\nRunning {batch_desc} with {len(batch['checks'])} checks: {', '.join(check_names)}")
        else:
            check = batch["checks"][0]
            print(f"\nRunning {batch_desc} - single check: {check.name}")
            print(f"Description: {check.description}")
        
        try:
            # Run the query
            query_id = client.run_query(batch["query"], filters)
            
            # Wait for completion
            if client.wait_for_query_completion(query_id):
                # Get results
                query_results = client.get_query_results(query_id)
                
                # Process the results for each check in the batch
                batch_results = process_batch_results(batch, query_results)
                results.update(batch_results)
            else:
                # Query failed - mark all checks in this batch as failed
                for check in batch["checks"]:
                    results[check.name] = {
                        "compliant": False,
                        "description": check.description,
                        "error": "Query aborted"
                    }
                
        except Exception as e:
            # Error occurred - mark all checks in this batch as failed
            for check in batch["checks"]:
                results[check.name] = {
                    "compliant": False,
                    "description": check.description,
                    "error": str(e)
                }
    
    return results

def load_config(config_path: str) -> Dict:
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config file {config_path}: {e}")
        sys.exit(1)

def load_all_checks(base_dir: str = None) -> List[ComplianceCheck]:
    """Load all STIG and threat hunt checks for the current OS."""
    if base_dir is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    os_type = get_os_type()
    checks = []

    # Load STIG checks
    stig_checks = load_stig_checks(os.path.join(base_dir, 'stig_checks'), os_type)
    for check in stig_checks:
        checks.append(ComplianceCheck(
            name=f"STIG-{check.get('id', 'unknown')}",
            description=check.get('title', 'Unknown STIG check'),
            query=check.get('query', ''),
            expected_result=check.get('condition')
        ))

    # Load threat hunt checks
    threat_hunt_dir = os.path.join(base_dir, 'threat_hunts', os_type)
    if os.path.exists(threat_hunt_dir):
        for filename in os.listdir(threat_hunt_dir):
            if filename.endswith(('.yaml', '.yml')):
                try:
                    with open(os.path.join(threat_hunt_dir, filename), 'r') as f:
                        hunt_data = yaml.safe_load(f)
                        for hunt in hunt_data.get('hunts', []):
                            checks.append(ComplianceCheck(
                                name=f"Hunt-{hunt.get('id', 'unknown')}",
                                description=hunt.get('description', 'Unknown threat hunt'),
                                query=hunt.get('query', ''),
                                expected_result=hunt.get('condition')
                            ))
                except Exception as e:
                    print(f"Error loading threat hunt file {filename}: {e}")

    return checks

def main():
    # Get config file path
    config_path = Path('config.yaml')
    if not config_path.exists():
        print(f"Config file not found: {config_path}")
        print("Please create a config.yaml file with your Centra API credentials")
        sys.exit(1)

    # Load configuration
    config_data = load_config(config_path)

    # Create Centra configuration
    config = CentraConfig(
        management_server=config_data['centra']['management_server'],
        api_port=config_data['centra'].get('api_port', 443),
        api_version=config_data['centra'].get('api_version', 'v1'),
        verify_ssl=config_data['centra'].get('verify_ssl', True)
    )

    try:
        # Initialize client
        client = CentraOSQueryClient(config)
        
        # Check if SSO token is provided in config
        sso_token = None
        if 'auth' in config_data['centra'] and 'sso_token' in config_data['centra']['auth']:
            sso_token = config_data['centra']['auth']['sso_token']
        
        # Authenticate with SSO token if available
        client.authenticate(sso_token)

        # Test a simple query
        test_query = "SELECT * FROM system_info LIMIT 1;"
        print(f"\nRunning test query: {test_query}")
        
        # Run query
        query_id = client.run_query(test_query)
        print(f"Query ID: {query_id}")
        
        # Wait for completion
        if client.wait_for_query_completion(query_id):
            # Get results
            results = client.get_query_results(query_id)
            print("\nQuery Results:")
            print(json.dumps(results, indent=2))
        else:
            print("Query failed or timed out")

    except Exception as e:
        print(f"Error running test query: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")

if __name__ == "__main__":
    main()
