
import requests


def get_mac_details(mac_address):
    url = "https://api.macvendors.com/"

    response = requests.get(f'{url}{mac_address}')
    if not response.ok:
        return None
    return response.content.decode()


if __name__ == '__main__':
    print(get_mac_details('f0:18:98:75:81:be'))
