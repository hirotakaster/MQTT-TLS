STARTUP(System.enableFeature(FEATURE_RETAINED_MEMORY)); //Required for NVRAM based entropy

SYSTEM_THREAD(ENABLED);
SYSTEM_MODE(SEMI_AUTOMATIC);

#include "Base64RK.h"  // or add 'dependencies.Base64RK=0.0.1' to the project.proerties file
#include "JWT.h"
#include "MQTT-TLS.h"  // or add 'dependencies.MQTT-TLS=0.2.20' to the project.proerties file

#define MAX_MQTT_PKT 2000
#define MQTT_JWT_EXPHOURS 24
#define MQTT_PORT 8883
#define MQTT_KEEP_ALIVE 120
#define JWT_SEED_LEN 600
#define JWT_SEED_LEN_INIT 455

retained static uint32_t jwtSeedLen = JWT_SEED_LEN_INIT;
retained static unsigned char jwtSeed[JWT_SEED_LEN];

//----GCP INTEGRATION SETUP ----------------------------------------------------
//----GOOGLE IOT CORE PEM-------------------------------------------------------
// use GlobalSign Root CA - R2
#define GOOGLE_IOT_CORE_CA_PEM \
"-----BEGIN CERTIFICATE----- \r\n"                                      \
//<YOUR GOOGLE ROOT KEY FROM EXAMPLE>
"-----END CERTIFICATE----- "

#define GOOGLE_IOT_CORE_PRIVATE_PEM \
"-----BEGIN PRIVATE KEY----- \r\n"\
//<YOUR PRIVATE KEY>
"-----END PRIVATE KEY-----"
const uint8_t gcp_private_pem[] = GOOGLE_IOT_CORE_PRIVATE_PEM;
const static uint16_t gcpKeyLen = sizeof(gcp_private_pem);

//const static char jwtToken[455] = "<GOLANG JWT TOKEN GNERATED ON LAPTOP>";
const static char gcIoTDevStr[85] = "projects/<YOUR PROJECT>/locations/us-central1/registries/<YOURREGISTRY>/devices/<YOUR DEVICE ID>";
const static char gcIoTPubTopic[42] = "/devices/<YOUR DEVICE ID>/events/<YOUT TOPIC>";
const static char gcIoTSubTopic[27] = "/devices/<YOUR DEVICE ID>/config";
const char googleIotCoreCaPem[] = GOOGLE_IOT_CORE_CA_PEM;

//Function Declarations
void callback(char* topic, byte* payload, unsigned int length);
uint8_t initGCPConnect(MQTT client);

// loop() runs continuously
void loop() {
  delay(10000);
  //Initialize the GCP Connection-----------------------------------------------
  //MQTT client("mqtt.googleapis.com", 8883, callback, 768);  // set max packet size to 768 for JWT password.
  Serial.println("loop:Initial Memory:" + String::format("%d",System.freeMemory()));
  MQTT client = MQTT("mqtt.googleapis.com", MQTT_PORT, MQTT_KEEP_ALIVE, callback, MAX_MQTT_PKT); //set to 768 + 32500 to include our photo
  initGCPConnect(client);  //Build a JWT, send it, and then clean it all up and discard to prepare RAM

  //TEMP REMOVAL
  //client.connect(gcIoTDevStr, "unused", jwtToken);
  //END TEST JWT

  Serial.println("loop:Connection Request Attempted");
  // subscribe to Google IoT Core
  if (client.isConnected()) client.subscribe(gcIoTSubTopic, MQTT::QOS1);

  //publish to Google IoT Core
  if (client.isConnected()) {client.publish(gcIoTPubTopic,"{\"data\":1}");

    Particle.process();
  } else {
    Serial.println("loop:MQTT Not Connected...");
  }
}

// recieve message
void callback(char* topic, byte* payload, unsigned int length) {
    Serial.println("callback:Callback Triggered");
    RGB.control(true);
    delay(2000);
    char p[length + 1];
    memcpy(p, payload, length);
    p[length] = NULL;
    String message(p);

    if (message.equals("RED"))
        RGB.color(255, 0, 0);
    else if (message.equals("GREEN"))
        RGB.color(0, 255, 0);
    else if (message.equals("BLUE"))
        RGB.color(0, 0, 255);
    else
        RGB.color(255, 255, 255);
    delay(1000);

    RGB.control(false);
}

uint8_t initGCPConnect(MQTT client){
  //TEST JWT
  //Instantiate a JWT class and the deconstruct after sending the token
  Serial.println("initGCPConnect:JWT Creation beginning:Memory:" + String::format("%d",System.freeMemory()));
  delay(10000);

  JWT* jwtToken = new JWT();

  Serial.println("initGCPConnect:JWT Creation Class Instantiated:Memory(2):" + String::format("%d",System.freeMemory()));
  const char projectId[12] = "<YOUR PROJECT ID>";

  char* token = jwtToken->createGCPJWT(projectId, gcp_private_pem, gcpKeyLen, MQTT_JWT_EXPHOURS, jwtSeed, (size_t) jwtSeedLen);
  delete jwtToken; //get rid of the residue
  if (token != nullptr) {

    Serial.println("initGCPConnect:JWT Signature:" + String::format("%s",token));
    client.enableTls(googleIotCoreCaPem, sizeof(googleIotCoreCaPem));
    client.connect(gcIoTDevStr, "unused", token);
    free(token);
    return 0;

  } else {
    Serial.println("initGCPConnect:JWT Token creation Failed");
    free(token);
    return 1;
  }
}
