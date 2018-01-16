#include "MQTT-TLS.h"

#include "application.h"

#define LOGGING

#define MQTTQOS0_HEADER_MASK        (0 << 1)
#define MQTTQOS1_HEADER_MASK        (1 << 1)
#define MQTTQOS2_HEADER_MASK        (2 << 1)

#define DUP_FLAG_OFF_MASK           (0<<3)
#define DUP_FLAG_ON_MASK            (1<<3)

MQTT::MQTT() {
    this->ip = NULL;
}

MQTT::MQTT(char* domain, uint16_t port, void (*callback)(char*,uint8_t*,unsigned int)) {
    this->initialize(domain, NULL, port, callback, MQTT_MAX_PACKET_SIZE);
}

MQTT::MQTT(char* domain, uint16_t port, void (*callback)(char*,uint8_t*,unsigned int), int maxpacketsize) {
    this->initialize(domain, NULL, port, callback, maxpacketsize);
}

MQTT::MQTT(uint8_t *ip, uint16_t port, void (*callback)(char*,uint8_t*,unsigned int)) {
    this->initialize(NULL, ip, port, callback, MQTT_MAX_PACKET_SIZE);
}

MQTT::MQTT(uint8_t *ip, uint16_t port, void (*callback)(char*,uint8_t*,unsigned int), int maxpacketsize) {
    this->initialize(NULL, ip, port, callback, maxpacketsize);
}

MQTT::~MQTT() {
    if (isConnected()) {
        disconnect();
        free(buffer);
    }
}

void MQTT::initialize(char* domain, uint8_t *ip, uint16_t port, void (*callback)(char*,uint8_t*,unsigned int), int maxpacketsize) {
    this->callback = callback;
    this->tls = false;
    this->tlsConnected = false;
    this->qoscallback = NULL;
    if (ip != NULL)
        this->ip = ip;
    if (domain != NULL)
        this->domain = domain;
    this->port = port;

    this->maxpacketsize = maxpacketsize;
    buffer = new uint8_t[this->maxpacketsize];
}

void MQTT::addQosCallback(void (*qoscallback)(unsigned int)) {
    this->qoscallback = qoscallback;
}

bool MQTT::connect(const char *id) {
    return connect(id,NULL,NULL,0,QOS0,0,0,true,MQTT_V311);
}

bool MQTT::connect(const char *id, const char *user, const char *pass) {
    return connect(id,user,pass,0,QOS0,0,0,true,MQTT_V311);
}

bool MQTT::connect(const char *id, const char* willTopic, EMQTT_QOS willQos, uint8_t willRetain, const char* willMessage) {
    return connect(id,NULL,NULL,willTopic,willQos,willRetain,willMessage,true,MQTT_V311);
}

bool MQTT::connect(const char *id, const char *user, const char *pass, const char* willTopic, EMQTT_QOS willQos, uint8_t willRetain, const char* willMessage, bool cleanSession, MQTT_VERSION version) {
    debug_tls("Connecting to MQTT broker ...");
    if (!isConnected()) {
        int result = 0;
        if (ip == NULL) {
            result = tcpClient.connect(this->domain.c_str(), this->port);
            if (tls) {
                mbedtls_ssl_set_hostname(&ssl, domain);
                result = (0 == this->handShakeTls() ? 1 : 0);
            }

        } else {
            result = tcpClient.connect(this->ip, this->port);
            if (tls) {
                char buffer[16];
                sprintf(buffer, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
                mbedtls_ssl_set_hostname(&ssl, buffer);
                result = (0 == this->handShakeTls() ? 1 : 0);
            }
        }

        if (result) {
            nextMsgId = 1;

            // Leave room in the buffer for header and variable length field
            uint16_t length = 5;

            const uint8_t MQTT_HEADER_V31[] = {0x00,0x06,'M','Q','I','s','d','p', MQTT_V31};
            const uint8_t MQTT_HEADER_V311[] = {0x00,0x04,'M','Q','T','T',MQTT_V311};

			      if (version == MQTT_V311) {
			          memcpy(buffer + length, MQTT_HEADER_V311, sizeof(MQTT_HEADER_V311));
				        length+=sizeof(MQTT_HEADER_V311);
			      } else {
			          memcpy(buffer + length, MQTT_HEADER_V31, sizeof(MQTT_HEADER_V31));
				        length+=sizeof(MQTT_HEADER_V31);
			      }

            uint8_t v = 0;

            if (cleanSession) {
                v|= 0x2;
            }

            if (willTopic) {
                v|= 0x04|(willQos<<3)|(willRetain<<5);
            }

            if(user != NULL) {
                v = v|0x80;

                if(pass != NULL) {
                    v = v|(0x80>>1);
                }
            }

            buffer[length++] = v;

            buffer[length++] = ((MQTT_KEEPALIVE) >> 8);
            buffer[length++] = ((MQTT_KEEPALIVE) & 0xFF);
            length = writeString(id, buffer, length);
            if (willTopic) {
                length = writeString(willTopic, buffer, length);
                length = writeString(willMessage, buffer, length);
            }

            if(user != NULL) {
                length = writeString(user,buffer,length);
                if(pass != NULL) {
                    length = writeString(pass,buffer,length);
                }
            }

            write(MQTTCONNECT, buffer, length-5);
            lastInActivity = lastOutActivity = millis();

            while (!available()) {
                unsigned long t = millis();
                if (t-lastInActivity > MQTT_KEEPALIVE*1000UL) {
                    debug_tls("MQTT connection timeout.\n");
                    disconnect();
                    return false;
                }
            }

            uint8_t llen;
            uint16_t len = readPacket(&llen);

            if (len == 4 && buffer[3] == 0) {
                lastInActivity = millis();
                pingOutstanding = false;
                debug_tls("MQTT connected.\n");
                return true;
            }
        }
        debug_tls("MQTT connection refused.\n");
        disconnect();
    }
    return false;
}

uint8_t MQTT::readByte() {
    if (tls == false) {
        while(!tcpClient.available()) {}
        return tcpClient.read();
    } else {
        uint8_t val = 0;
        uint8_t buff;

        if (tlsConnected) {
            while (1) {
                int ret = mbedtls_ssl_read(&ssl, &buff, 1);
                if (ret < 0) {
                      switch (ret) {
                        case MBEDTLS_ERR_SSL_WANT_READ:
                          break;
                      case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
                      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                      default:
                          disconnect();
                          return -1;
                    }
                } else {
                    return buff;
                }
            }
        } else {
            return -1;
        }
    }
}

uint16_t MQTT::readPacket(uint8_t* lengthLength) {
    uint16_t len = 0;
    buffer[len++] = readByte();
    bool isPublish = (buffer[0]&0xF0) == MQTTPUBLISH;
    uint32_t multiplier = 1;
    uint16_t length = 0;
    uint8_t digit = 0;
    uint16_t skip = 0;
    uint8_t start = 0;

    do {
        digit = readByte();
        buffer[len++] = digit;
        length += (digit & 127) * multiplier;
        multiplier *= 128;
    } while ((digit & 128) != 0);
    *lengthLength = len-1;

    if (isPublish) {
        // Read in topic length to calculate bytes to skip over for Stream writing
        buffer[len++] = readByte();
        buffer[len++] = readByte();
        skip = (buffer[*lengthLength+1]<<8)+buffer[*lengthLength+2];
        start = 2;
        if (buffer[0] & MQTTQOS1_HEADER_MASK) {
            // skip message id
            skip += 2;
        }
    }

    for (uint16_t i = start;i<length;i++) {
        digit = readByte();
        if (len < this->maxpacketsize) {
            buffer[len] = digit;
        }
        len++;
    }

    if (len > this->maxpacketsize) {
        len = 0; // This will cause the packet to be ignored.
    }

    return len;
}

bool MQTT::loop() {
    if (isConnected()) {
        unsigned long t = millis();
        if ((t - lastInActivity > MQTT_KEEPALIVE*1000UL) || (t - lastOutActivity > MQTT_KEEPALIVE*1000UL)) {
            if (pingOutstanding) {
                disconnect();
                return false;
            } else {
                buffer[0] = MQTTPINGREQ;
                buffer[1] = 0;
                netWrite(buffer,2);
                lastOutActivity = t;
                lastInActivity = t;
                pingOutstanding = true;
            }
        }
        if (available()) {
            uint8_t llen;
            uint16_t len = readPacket(&llen);
            uint16_t msgId = 0;
            uint8_t *payload;
            if (len > 0) {
                lastInActivity = t;
                uint8_t type = buffer[0]&0xF0;
                if (type == MQTTPUBLISH) {
                    if (callback) {
                        uint16_t tl = (buffer[llen+1]<<8)+buffer[llen+2];
                        char topic[tl+1];
                        for (uint16_t i=0;i<tl;i++) {
                            topic[i] = buffer[llen+3+i];
                        }
                        topic[tl] = 0;
                        // msgId only present for QOS>0
                        if ((buffer[0]&0x06) == MQTTQOS1_HEADER_MASK) {
                            msgId = (buffer[llen+3+tl]<<8)+buffer[llen+3+tl+1];
                            payload = buffer+llen+3+tl+2;
                            callback(topic,payload,len-llen-3-tl-2);

                            buffer[0] = MQTTPUBACK;
                            buffer[1] = 2;
                            buffer[2] = (msgId >> 8);
                            buffer[3] = (msgId & 0xFF);
                            netWrite(buffer,4);
                            lastOutActivity = t;
                        } else {
                            payload = buffer+llen+3+tl;
                            callback(topic,payload,len-llen-3-tl);
                        }
                    }
                } else if (type == MQTTPUBACK || type == MQTTPUBREC) {
                    if (qoscallback) {
                        // msgId only present for QOS==0
                        if (len == 4 && (buffer[0]&0x06) == MQTTQOS0_HEADER_MASK) {
                            msgId = (buffer[2]<<8)+buffer[3];
                            this->qoscallback(msgId);
                        }
                    }
                } else if (type == MQTTPUBCOMP) {
                    // TODO:if something...
                } else if (type == MQTTSUBACK) {
                    // if something...
                } else if (type == MQTTPINGREQ) {
                    buffer[0] = MQTTPINGRESP;
                    buffer[1] = 0;
                    netWrite(buffer,2);
                } else if (type == MQTTPINGRESP) {
                    pingOutstanding = false;
                }
            }
        }
        return true;
    }
    return false;
}

bool MQTT::publish(const char* topic, const char* payload) {
    return publish(topic, (uint8_t*)payload, strlen(payload), false, QOS0, NULL);
}

bool MQTT::publish(const char * topic, const char* payload, EMQTT_QOS qos, bool dup, uint16_t *messageid) {
    return publish(topic, (uint8_t*)payload, strlen(payload), false, qos, dup, messageid);
}

bool MQTT::publish(const char * topic, const char* payload, EMQTT_QOS qos, uint16_t *messageid) {
    return publish(topic, (uint8_t*)payload, strlen(payload), false, qos, messageid);
}

bool MQTT::publish(const char* topic, const uint8_t* payload, unsigned int plength) {
    return publish(topic, payload, plength, false, QOS0, NULL);
}

bool MQTT::publish(const char* topic, const uint8_t* payload, unsigned int plength, EMQTT_QOS qos, bool dup, uint16_t *messageid) {
    return publish(topic, payload, plength, false, qos, dup, messageid);
}

bool MQTT::publish(const char* topic, const uint8_t* payload, unsigned int plength, EMQTT_QOS qos, uint16_t *messageid) {
    return publish(topic, payload, plength, false, qos, messageid);
}

bool MQTT::publish(const char* topic, const uint8_t* payload, unsigned int plength, bool retain) {
    return publish(topic, payload, plength, retain, QOS0, NULL);
}

bool MQTT::publish(const char* topic, const uint8_t* payload, unsigned int plength, bool retain, EMQTT_QOS qos, uint16_t *messageid) {
    return publish(topic, payload, plength, retain, qos, false, messageid);
}

bool MQTT::publish(const char* topic, const uint8_t* payload, unsigned int plength, bool retain, EMQTT_QOS qos, bool dup, uint16_t *messageid) {
    if (isConnected()) {
        // Leave room in the buffer for header and variable length field
        uint16_t length = 5;
        memset(buffer, 0, sizeof(buffer));

        length = writeString(topic, buffer, length);

        if (qos == QOS2 || qos == QOS1) {
            nextMsgId += 1;
            buffer[length++] = (nextMsgId >> 8);
            buffer[length++] = (nextMsgId & 0xFF);
            if (messageid != NULL)
                *messageid = nextMsgId++;
        }

        for (uint16_t i=0; i < plength && length < this->maxpacketsize; i++) {
            buffer[length++] = payload[i];
        }

        uint8_t header = MQTTPUBLISH;
        if (retain) {
            header |= 1;
        }

        if (dup) {
            header |= DUP_FLAG_ON_MASK;
        }

        if (qos == QOS2)
            header |= MQTTQOS2_HEADER_MASK;
        else if (qos == QOS1)
            header |= MQTTQOS1_HEADER_MASK;
        else
            header |= MQTTQOS0_HEADER_MASK;

        return write(header, buffer, length-5);
    }
    return false;
}

bool MQTT::publishRelease(uint16_t messageid) {
    if (isConnected()) {
        uint16_t length = 0;
        buffer[length++] = MQTTPUBREL | MQTTQOS1_HEADER_MASK;
        buffer[length++] = 2;
        buffer[length++] = (messageid >> 8);
        buffer[length++] = (messageid & 0xFF);
        return netWrite(buffer, length);
    }
    return false;
}


bool MQTT::write(uint8_t header, uint8_t* buf, uint16_t length) {
    uint8_t lenBuf[4];
    uint8_t llen = 0;
    uint8_t digit;
    uint8_t pos = 0;
    uint16_t rc;
    uint16_t len = length;
    do {
        digit = len % 128;
        len = len / 128;
        if (len > 0) {
            digit |= 0x80;
        }
        lenBuf[pos++] = digit;
        llen++;
    } while(len > 0);

    buf[4-llen] = header;
    for (int i = 0; i < llen; i++) {
        buf[5-llen+i] = lenBuf[i];
    }
    rc = netWrite(buf+(4-llen), length+1+llen);

    lastOutActivity = millis();
    return (rc == 1+llen+length);
}

bool MQTT::subscribe(const char* topic) {
    return subscribe(topic, QOS0);
}

bool MQTT::subscribe(const char* topic, EMQTT_QOS qos) {
    if (qos < 0 || qos > 1)
        return false;

    if (isConnected()) {
        // Leave room in the buffer for header and variable length field
        uint16_t length = 5;
        nextMsgId++;
        if (nextMsgId == 0) {
            nextMsgId = 1;
        }
        buffer[length++] = (nextMsgId >> 8);
        buffer[length++] = (nextMsgId & 0xFF);
        length = writeString(topic, buffer,length);
        buffer[length++] = qos;
        return write(MQTTSUBSCRIBE | MQTTQOS1_HEADER_MASK,buffer,length-5);
    }
    return false;
}

bool MQTT::unsubscribe(const char* topic) {
    if (isConnected()) {
        uint16_t length = 5;
        nextMsgId++;
        if (nextMsgId == 0) {
            nextMsgId = 1;
        }
        buffer[length++] = (nextMsgId >> 8);
        buffer[length++] = (nextMsgId & 0xFF);
        length = writeString(topic, buffer,length);
        return write(MQTTUNSUBSCRIBE | MQTTQOS1_HEADER_MASK,buffer,length-5);
    }
    return false;
}

void MQTT::disconnect() {
    debug_tls("mqtt disconnected\n");

    buffer[0] = MQTTDISCONNECT;
    buffer[1] = 0;
    netWrite(buffer,2);

    if (tls) {
        debug_tls("tls close\n");
        tlsConnected = false;
        tls = false;
        mbedtls_x509_crt_free (&cacert);
        mbedtls_ssl_config_free (&conf);
        mbedtls_ssl_free (&ssl);
    }
    tcpClient.stop();
    lastInActivity = lastOutActivity = millis();
}

uint16_t MQTT::writeString(const char* string, uint8_t* buf, uint16_t pos) {
    const char* idp = string;
    uint16_t i = 0;
    pos += 2;
    while (*idp && pos < this->maxpacketsize) {
        buf[pos++] = *idp++;
        i++;
    }
    buf[pos-i-2] = (i >> 8);
    buf[pos-i-1] = (i & 0xFF);
    return pos;
}


uint16_t MQTT::netWrite(unsigned char *buff, int length) {
    debug_tls("netWrite!!\n");

    for (int i = 0 ; i < length; i++) {
      if (buff[i] > ' ' && buff[i] < 127) {
        debug_tls("%c", buff[i]);
      } else {
        debug_tls("%02X ", buff[i]);
      }
    }
    debug_tls("\n");

    if (tls == false) {
        return tcpClient.write(buff, length);
    } else {
        return mbedtls_ssl_write(&ssl, buff, length);
    }
}


bool MQTT::isConnected() {
    bool rc = (int)tcpClient.connected();
    if (tls)
        return tlsConnected;
    return rc;
}

bool MQTT::available() {
    return tcpClient.available();
}

int MQTT::send_Tls(void *ctx, const unsigned char *buf, size_t len) {
  MQTT *sock = (MQTT *)ctx;

  if (!sock->tcpClient.connected()) {
    return -1;
  }

  int ret = sock->tcpClient.write(buf, len);
  if (ret == 0) {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  sock->tcpClient.flush();
  return ret;
}

int MQTT::recv_Tls(void *ctx, unsigned char *buf, size_t len) {
  MQTT *sock = (MQTT *)ctx;
  if (!sock->tcpClient.connected()) {
    return -1;
  }

  if (sock->tcpClient.available() == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  int ret = sock->tcpClient.read(buf, len);
  if (ret == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return ret;
}

int MQTT::rng_Tls(void* handle, uint8_t* data, const size_t len_) {
  size_t len = len_;
  while (len>=4) {
      *((uint32_t*)data) = HAL_RNG_GetRandomNumber();
      data += 4;
      len -= 4;
  }

  while (len-->0) {
      *data++ = HAL_RNG_GetRandomNumber();
  }
  return 0;
}

void MQTT::debug_Tls( void *ctx, int level,
                      const char *file, int line,
                      const char *str ) {
    ((void) level);
    debug_tls("%s:%04d: %s", file, line, str);
}


int MQTT::enableTls(const char *rootCaPem, const size_t rootCaPemSize) {
    return this->enableTls(rootCaPem, rootCaPemSize, NULL, 0, NULL, 0);
}

int MQTT::enableTls(const char *rootCaPem, const size_t rootCaPemSize,
                    const char *clientCertPem, const size_t clientCertPemSize,
                    const char *clientKeyPem, const size_t clientKeyPemSize) {
    int ret;
    tls = true;

    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);

    mbedtls_ssl_conf_dbg(&conf, &MQTT::debug_Tls, nullptr);
    #if defined(MBEDTLS_DEBUG_C)
      mbedtls_debug_set_threshold(DEBUG_TLS_CORE_LEVEL);
    #endif

    if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)rootCaPem, rootCaPemSize)) < 0) {
      debug_tls(" enableTls mbedtls_x509_crt_parse error : %d\n", ret);
      return ret;
    }

    if (clientCertPem != NULL && clientCertPemSize > 0) {
      if ((ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char *)clientCertPem, clientCertPemSize)) < 0) {
        debug_tls(" tlsClientKey mbedtls_x509_crt_parse error : %d\n", ret);
        return ret;
      }
    }

    if (clientKeyPem != NULL && clientKeyPemSize > 0) {
      if ((ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *)clientKeyPem, clientKeyPemSize, NULL, 0)) != 0) {
        debug_tls(" tlsClientKey mbedtls_pk_parse_key error : %d\n", ret);
        return ret;
      }
    }

    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                   MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
      return ret;
    }
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_verify(&conf, &MQTT::veryfyCert_Tls, NULL);

    // if server certificates is not valid, connection will success. check certificates on verify() function.
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&conf, &MQTT::rng_Tls, nullptr);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);

    if (clientCertPem != NULL && clientKeyPem != NULL) {
      mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
    }

    if((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
      return ret;
    }

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
    mbedtls_ssl_set_bio(&ssl, this, &MQTT::send_Tls,  &MQTT::recv_Tls, nullptr);
    return 0;
/*
    int ret;
    tls = true;

    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ssl_conf_rng(&conf, &MQTT::rng_Tls, nullptr);
    mbedtls_ssl_conf_dbg(&conf, &MQTT::debug_Tls, nullptr);

    #if defined(MBEDTLS_DEBUG_C)
      mbedtls_debug_set_threshold(DEBUG_TLS_CORE_LEVEL);
    #endif

    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
      return ret;
    }

    if ((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)rootCaPem, rootCaPemSize)) < 0) {
      return ret;
    }
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);

    // if server certificates is not valid, connection will success. check certificates on verify() function.
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_init(&ssl);
    if((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
      return ret;
    }

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
    mbedtls_ssl_set_bio(&ssl, this, &MQTT::send_Tls,  &MQTT::recv_Tls, nullptr);
    return 0;
*/
}


int MQTT::handShakeTls() {
  int ret;
  debug_tls("hand shake start\n");
  do {
      while (ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
          ret = mbedtls_ssl_handshake_client_step(&ssl);
          if (ret != 0)
              break;
      }
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  debug_tls("%s, ret = %d\n", "handshake done", ret);
  if (ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
      tlsConnected = true;
      debug_tls("tls connected\n");
      return 0;
  }
  return ret;
}

bool MQTT::verify() {
  int ret;
  if ((ret = mbedtls_ssl_get_verify_result(&ssl)) != 0 ) {
    char vrfy_buf[512];
    mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", ret );
    debug_tls("%s\n", vrfy_buf);
    return false;
  }
  return true;
}

int MQTT::veryfyCert_Tls(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
  char buf[1024];
  ((void) data);

  debug_tls("Verify requested for (Depth %d):\n", depth);
  mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
  debug_tls("%s", buf);

  if((*flags) == 0) {
    debug_tls("  This certificate has no flags\n");
  } else {
    debug_tls(buf, sizeof(buf), "  ! ", *flags);
    debug_tls("%s\n", buf);
  }
  return 0;
}
