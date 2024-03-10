import requests
import json
import os

# Функция для получения данных по CVE из Wazuh
def get_cve_data():
    # Замените 'your_wazuh_address' и 'your_wazuh_port' на соответствующие значения
    url = 'https://192.168.200.16:55000/vulnerability/003/summary/cve'
    
    # Указываем токен авторизации
    token = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzA5OTIyNzU2LCJleHAiOjE3MDk5MjM2NTYsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AdsG8wd0JXFOGcrPP7HLp_ashqFEnuURaDBwxTigcNkgV3UU1oBtje2BXMmxxgjbgoKk74SeLS-Ei1I__NAaRV7NAeZ4_Vr0FEvimkstWePNTN'
    print(token)
    
    # Создаем заголовок с токеном
    headers = {'Authorization': f'Bearer {token}'}
    
    # Получаем данные по CVE из Wazuh с использованием токена и отключенной проверкой на сертификат

    response = requests.get(url, headers=headers,verify=False)

    if response.status_code == 200:
        cve_data = response.json()
        return cve_data
    else:
        print("Failed to retrieve CVE data from Wazuh.")
        return None

# Функция для поиска CVE на Exploit-DB

def search_exploit_db(cve):
    url = f"https://www.exploit-db.com/search?cve={cve}"
    response = requests.get(url)

    if response.status_code == 200:
        # Предполагается, что первый результат является наиболее актуальным
        exploit_url = response.url
        exploit_id = exploit_url.split('/')[-1]
        return exploit_id
    else:
        print("Failed to search Exploit-DB for CVE.")
        return None

# Функция для загрузки эксплоита с Exploit-DB
def download_exploit(exploit_id, output_dir):
    url = f"https://www.exploit-db.com/download/{exploit_id}"
    response = requests.get(url)

    if response.status_code == 200:
        exploit_content = response.content
        exploit_file_path = os.path.join(output_dir, f"{exploit_id}.zip")
        with open(exploit_file_path, 'wb') as f:
            f.write(exploit_content)
        return exploit_file_path
    else:
        print("Failed to download exploit from Exploit-DB.")
        return None

# Функция для создания нового adversary в Mitre Caldera с передачей Cookie для авторизации
def create_adversary(cve):
    url = "http://192.168.200.6:8888/api/v2/adversaries"
    headers = {'Content-Type': 'application/json', 'Cookie': 'API_SESSION="gAAAAABl6104bRsr-m7XNyIOvjKP11xuGwCNHMmtvcFZazUxp8riFIlDxvdbu3ccxIWEKenBRS7RJjRseBTJSwS86tTnPIXtb8DuDbfmT7pd7e6RmCQPUBhggN-XOa9V_QESopOZvGkUeiWbOudQ590tRL4sMyGWcouxAm20Ne8rHiR6xu1BoU4="'}
    data = {
        "name": f"CVE_{cve}_Adversary",
        "description": f"Adversary for exploiting CVE {cve}"
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        adversary_id = response.json()['id']
        print(f"New adversary created with ID: {adversary_id}")
        return adversary_id
    else:
        print("Failed to create adversary in Mitre Caldera.")
        return None

# Функция для создания нового сценария в Mitre Caldera
def create_scenario(cve, adversary_id):
    url = "http://192.168.200.6:8888/api/v2/scenarios"
    headers = {'Content-Type': 'application/json', 'Cookie': 'API_SESSION="gAAAAABl6104bRsr-m7XNyIOvjKP11xuGwCNHMmtvcFZazUxp8riFIlDxvdbu3ccxIWEKenBRS7RJjRseBTJSwS86tTnPIXtb8DuDbfmT7pd7e6RmCQPUBhggN-XOa9V_QESopOZvGkUeiWbOudQ590tRL4sMyGWcouxAm20Ne8rHiR6xu1BoU4="'}}

    data = {
        "name": f"CVE_{cve}_Scenario",
        "description": f"Scenario for exploiting CVE {cve}",
        "adversary_id": adversary_id,
        "steps": []  # Добавьте шаги сценария при необходимости
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        scenario_id = response.json()['id']
        print(f"New scenario created with ID: {scenario_id}")
        return scenario_id
    else:
        print("Failed to create scenario in Mitre Caldera.")
        return None

# Функция для создания новой кампании в Mitre Caldera
def create_campaign(scenario_id):
    url = "http://192.168.200.6:8888/api/v2/campaigns"
    headers = {'Content-Type': 'application/json', 'Cookie': 'API_SESSION="gAAAAABl6104bRsr-m7XNyIOvjKP11xuGwCNHMmtvcFZazUxp8riFIlDxvdbu3ccxIWEKenBRS7RJjRseBTJSwS86tTnPIXtb8DuDbfmT7pd7e6RmCQPUBhggN-XOa9V_QESopOZvGkUeiWbOudQ590tRL4sMyGWcouxAm20Ne8rHiR6xu1BoU4="'}}

    data = {
        "name": "CVE_Exploitation_Campaign",
        "adversary": "CVE_2016-7182_Adversary",  
        "objective": "Exploit CVE vulnerabilities",
        "start": "2024-03-04T12:00:00Z",  # дата и время начала кампании
        "finish": "2024-03-11T12:00:00Z",  # дата и время завершения кампании
        "scenarios": [scenario_id]
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        campaign_id = response.json()['id']
        print(f"New campaign created with ID: {campaign_id}")
        return campaign_id
    else:
        print("Failed to create campaign in Mitre Caldera.")
        return None


# Функция для запуска кампании в Mitre Caldera
def run_campaign(campaign_id):
    url = f"http://192.168.200.6:8888/api/v2/campaigns/{campaign_id}/start"
    headers = {'Content-Type': 'application/json', 'Cookie': 'API_SESSION="gAAAAABl6104bRsr-m7XNyIOvjKP11xuGwCNHMmtvcFZazUxp8riFIlDxvdbu3ccxIWEKenBRS7RJjRseBTJSwS86tTnPIXtb8DuDbfmT7pd7e6RmCQPUBhggN-XOa9V_QESopOZvGkUeiWbOudQ590tRL4sMyGWcouxAm20Ne8rHiR6xu1BoU4="'}}}

    response = requests.post(url, headers=headers)

    if response.status_code == 200:
        print("Campaign started successfully.")
    else:
        print("Failed to start campaign in Mitre Caldera.")

def main():
    cve_data = get_cve_data()
    if cve_data:
        for cve_entry in cve_data:
            exploit_id = search_exploit_db(cve_entry['cve'])
            if exploit_id:
                download_exploit(exploit_id, "exploits")
                print(f"Exploit for {cve_entry['cve']} downloaded successfully.")
            else:
                print(f"No exploit found for {cve_entry['cve']}.")

            adversary_id = create_adversary(cve_entry['cve'])
            if adversary_id:
                scenario_id = create_scenario(cve_entry['cve'], adversary_id)
                if scenario_id:
                    campaign_id = create_campaign(scenario_id)
                    if campaign_id:
                        run_campaign(campaign_id)
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()
