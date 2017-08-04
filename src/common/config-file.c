/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org>
 * 				 2008-2011 - Robert Hogan <robert@roberthogan.net>
 * 				 	  2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "config-file.h"
#include "log.h"
#include "utils.h"

/*
 * These are the torsocks.conf string values.
 */
static const char *conf_toraddr_str = "TorAddress";
static const char *conf_torport_str = "TorPort";
static const char *conf_onion_str = "OnionAddrRange";
static const char *conf_socks5_user_str = "SOCKS5Username";
static const char *conf_socks5_pass_str = "SOCKS5Password";
static const char *conf_allow_inbound_str = "AllowInbound";
static const char *conf_allow_outbound_localhost_str = "AllowOutboundLocalhost";
static const char *conf_isolate_pid_str = "IsolatePID";
static const char *conf_port_list_type_str = "PortsType";
static const char *conf_port_list_str = "PortsList";

/*
 * Once this value reaches 2, it means both user and password for a SOCKS5
 * connection has been set thus use them./
 */
static unsigned int both_socks5_pass_user_set;

/*
 * Username format for the IsolatePID option. Format is:
 *   'torsocks-' PID ':' TIME
 */
static const char *isolate_username_fmt = "torsocks-%ld:%lld";
/* Default password for the IsolatePID option. */
static const char *isolate_password = "0";

/*
 * Set the onion pool address range in the configuration object using the value
 * found in the conf file.
 *
 * Return 0 on success or else a negative value.
 */
static int set_onion_info(const char *addr, struct configuration *config)
{
	int ret;
	unsigned long bit_mask;
	char *ip = NULL, *mask = NULL;
	in_addr_t net;

	assert(addr);
	assert(config);

	ip = strchr(addr, '/');
	if (!ip) {
		ERR("[config] Invalid %s value for %s", addr, conf_onion_str);
		ret = -EINVAL;
		goto error;
	}

	mask = strdup(addr + (ip - addr) + 1);
	ip = strndup(addr, ip - addr);
	if (!ip || !mask) {
		PERROR("[config] strdup onion addr");
		ret = -ENOMEM;
		goto error;
	}

	net = inet_addr(ip);
	if (net == INADDR_NONE) {
		ERR("[config] Invalid IP subnet %s for %s", ip, conf_onion_str);
		ret = -EINVAL;
		goto error;
	}

	/* Expressed in base 10. */
	bit_mask = strtoul(mask, NULL, 10);
	if (bit_mask == ULONG_MAX) {
		ERR("[config] Invalid mask %s for %s", mask, conf_onion_str);
		ret = -EINVAL;
		goto error;
	}

	memcpy(&config->conf_file.onion_base, &net,
			sizeof(config->conf_file.onion_base));
	config->conf_file.onion_mask = (uint8_t) bit_mask;

	DBG("[config] Onion address range set to %s", addr);
	ret = 0;

error:
	free(ip);
	free(mask);
	return ret;
}

/*
 * Parse a single line from a configuration file and set the value found in
 * the configuration object.
 *
 * Return 0 on success or else a negative value.
 */
static int parse_config_line(const char *line, struct configuration *config)
{
	int ret, nb_token;
	char *tokens[DEFAULT_MAX_CONF_TOKEN];

	assert(line);
	assert(config);

	/*
	 * The line is tokenized and each token is NULL terminated.
	 */
	nb_token = utils_tokenize_ignore_comments(line, DEFAULT_MAX_CONF_TOKEN,
			tokens);
	if (nb_token <= 0) {
		/* Nothing on this line that is useful to parse. */
		ret = 0;
		goto end;
	}

	if (!strcmp(tokens[0], conf_toraddr_str)) {
		ret = conf_file_set_tor_address(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_torport_str)) {
		ret = conf_file_set_tor_port(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_onion_str)) {
		ret = set_onion_info(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_socks5_user_str)) {
		ret = conf_file_set_socks5_user(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_socks5_pass_str)) {
		ret = conf_file_set_socks5_pass(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_allow_inbound_str)) {
		ret = conf_file_set_allow_inbound(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_allow_outbound_localhost_str)) {
		ret = conf_file_set_allow_outbound_localhost(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_isolate_pid_str)) {
		ret = conf_file_set_isolate_pid(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_port_list_type_str)) {
		ret = conf_file_set_port_list_type(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else if (!strcmp(tokens[0], conf_port_list_str)) {
		ret = conf_file_set_port_list(tokens[1], config);
		if (ret < 0) {
			goto error;
		}
	} else {
		WARN("Config file contains unknown value: %s", line);
	}

	/* Everything went well. */
	ret = 0;

end:
error:
	return ret;
}

/*
 * Parse the configuration file with the given file pointer into the
 * configuration object.
 *
 * Return 0 on success or else a negative value.
 */
static int parse_config_file(FILE *fp, struct configuration *config)
{
	int ret = -1;
	/* Usually, this value is 8192 on most Unix systems. */
	char line[BUFSIZ];

	assert(fp);
	assert(config);

	while (fgets(line, sizeof(line), fp) != NULL) {
		/*
		 * Remove the \n at the end of the buffer and replace it by a NULL
		 * bytes so we handle the line without this useless char.
		 */
		if (strlen(line) > 0) {
			line[strlen(line) - 1] = '\0';
		}

		ret = parse_config_line(line, config);
		if (ret < 0) {
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Set the given string port in a configuration object.
 *
 * Return 0 on success or else a negative EINVAL if the port is equal to 0 or
 * over 65535.
 */
ATTR_HIDDEN
int conf_file_set_tor_port(const char *port, struct configuration *config)
{
	int ret = 0;
	char *endptr;
	unsigned long _port;

	assert(port);
	assert(config);

	/* Let's avoid an integer overflow here ;). */
	_port = strtoul(port, &endptr, 10);
	if (_port == 0 || _port > 65535) {
		ret = -EINVAL;
		ERR("Config file invalid port: %s", port);
		goto error;
	}

	config->conf_file.tor_port = (in_port_t) _port;

	DBG("Config file setting tor port to %lu", _port);

error:
	return ret;
}

/*
 * Set the given string address in a configuration object.
 *
 * Return 0 on success or else a negative value. On error, the address was not
 * recognized.
 */
ATTR_HIDDEN
int conf_file_set_tor_address(const char *addr, struct configuration *config)
{
	int ret;

	assert(addr);
	assert(config);

	ret = utils_is_address_ipv4(addr);
	if (ret == 1 ) {
		config->conf_file.tor_domain = CONNECTION_DOMAIN_INET;
	} else {
		ret = utils_is_address_ipv6(addr);
		if (ret != 1) {
			/* At this point, the addr is either v4 nor v6 so error. */
			ERR("Config file unknown tor address: %s", addr);
			goto error;
		}
		config->conf_file.tor_domain = CONNECTION_DOMAIN_INET6;
	}

	if (config->conf_file.tor_address != NULL) {
		free(config->conf_file.tor_address);
		config->conf_file.tor_address = NULL;
	}

	config->conf_file.tor_address = strdup(addr);
	if (config->conf_file.tor_address == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	DBG("Config file setting tor address to %s", addr);
	ret = 0;

error:
	return ret;
}

/*
 * Set the SOCKS5 username to the given configuration.
 *
 * Return 0 on success else a negative value.
 */
ATTR_HIDDEN
int conf_file_set_socks5_user(const char *username,
		struct configuration *config)
{
	int ret;

	assert(username);
	assert(config);

	if (strlen(username) > sizeof(config->conf_file.socks5_username)) {
		ERR("[config] Invalid %s value for %s", username,
				conf_socks5_user_str);
		ret = -EINVAL;
		goto error;
	}

	strncpy(config->conf_file.socks5_username, username, strlen(username));
	if (++both_socks5_pass_user_set == 2) {
		config->socks5_use_auth = 1;
	}
	DBG("[config] %s set to %s", conf_socks5_user_str, username);
	return 0;

error:
	return ret;
}

/*
 * Set the SOCKS5 password to the given configuration.
 *
 * Return 0 on success else a negative value.
 */
ATTR_HIDDEN
int conf_file_set_socks5_pass(const char *password,
		struct configuration *config)
{
	int ret;

	assert(password);
	assert(config);

	if (strlen(password) > sizeof(config->conf_file.socks5_password)) {
		ERR("[config] Invalid %s value for %s", password,
				conf_socks5_pass_str);
		ret = -EINVAL;
		goto error;
	}

	strncpy(config->conf_file.socks5_password, password, strlen(password));
	if (++both_socks5_pass_user_set == 2) {
		config->socks5_use_auth = 1;
	}
	DBG("[config] %s set to %s", conf_socks5_pass_str, password);
	return 0;

error:
	return ret;
}

/*
 * Set the allow inbound option for the given config.
 *
 * Return 0 if option is off, 1 if on and negative value on error.
 */
ATTR_HIDDEN
int conf_file_set_allow_inbound(const char *val, struct configuration *config)
{
	int ret;

	assert(val);
	assert(config);

	ret = atoi(val);
	if (ret == 0) {
		config->allow_inbound = 0;
		DBG("[config] Inbound connections disallowed.");
	} else if (ret == 1) {
		config->allow_inbound = 1;
		DBG("[config] Inbound connections allowed.");
	} else {
		ERR("[config] Invalid %s value for %s", val, conf_allow_inbound_str);
		ret = -EINVAL;
	}

	return ret;
}

/*
 * Set the allow outbound localhost option for the given config.
 *
 * Return 0 if option is off, 1 if on and negative value on error.
 */
ATTR_HIDDEN
int conf_file_set_allow_outbound_localhost(const char *val,
		struct configuration *config)
{
	int ret;

	assert(val);
	assert(config);

	ret = atoi(val);
	if (ret == 0) {
		config->allow_outbound_localhost = 0;
		DBG("[config] Outbound localhost connections disallowed.");
	} else if (ret == 1) {
		config->allow_outbound_localhost = 1;
		DBG("[config] Outbound localhost connections allowed.");
	} else if (ret == 2) {
		config->allow_outbound_localhost = 2;
		DBG("[config] Outbound localhost connections + UDP allowed.");
	} else {
		ERR("[config] Invalid %s value for %s", val,
				conf_allow_outbound_localhost_str);
		ret = -EINVAL;
	}

	return ret;
}

/*
 * Set the isolate PID option for the given config.
 *
 * Return 0 if optiuon is off, 1 if on and negative value on error.
 */
ATTR_HIDDEN
int conf_file_set_isolate_pid(const char *val, struct configuration *config)
{
	int ret;

	assert(val);
	assert(config);

	ret = atoi(val);
	if (ret == 0) {
		config->isolate_pid = 0;
		DBG("[config] PID isolation disabled.");
	} else if (ret == 1) {
		config->isolate_pid = 1;
		DBG("[config] PID isolation enabled.");
	} else {
		ERR("[config] Invalid %s value for %s", val,
				conf_isolate_pid_str);
		ret = -EINVAL;
	}

	return ret;
}
ATTR_HIDDEN
int conf_file_set_port_list_type(const char *val, struct configuration *config)
{
	int ret;

    assert(val);
    assert(config);

	ret = atoi(val);
	if (ret == 0) {
		config->ports.type = 0;
		DBG("[config] Ports list disabled.");
    } else if (ret == 1) {
		config->ports.type = 1;
		DBG("[config] Ports white list enabled.");
    } else if (ret == 2) {
		config->ports.type = 2;
		DBG("[config] Ports black list enabled.");
	} else {
		ERR("[config] Invalid %s value for %s", val,
				conf_port_list_type_str);
		ret = -EINVAL;
	}
    return ret;
}

ATTR_HIDDEN
int conf_file_add_ports_range(struct ports_list *ports, unsigned short beg, unsigned short end)
{
    size_t i;
    struct ports_range *range = NULL;

    assert(ports);

    if (beg > end) {
		ERR("[config] Invalid range %hu - %hu", beg, end);
		return -EINVAL;
    }
    for (i=0; i < ports->ranges_num; ++i) {
        range = &ports->ranges[i];
        if (range->beginning <= beg && range->ending >= end) {
            DBG("[config] Ports range %hu - %hu swarms new range %hu - %hu",
                    range->beginning, range->ending, beg, end);
            return 0;
        }
        if (range->beginning >= beg && range->ending <= end) {
            DBG("[config] Ports range %hu - %hu swarmed by new range %hu - %hu",
                    range->beginning, range->ending, beg, end);
            range->beginning = range->ending = 0;
            i = 0;
        }
        if (range->beginning <= end && end <= range->ending) {
            DBG("[config] Ports range %hu - %hu overlaps with new range "
                    "%hu - %hu", range->beginning, range->ending, beg, end);
            end = range->ending;
            range->beginning = range->ending = 0;
            i = 0;
        }
        if (beg <= range->ending && range->ending <= end) {
            DBG("[config] Ports range %hu - %hu overlaps with new range "
                    "%hu - %hu", range->beginning, range->ending, beg, end);
            beg = range->beginning;
            range->beginning = range->ending = 0;
            i = 0;
        }
    }
    for (i=0; i < ports->ranges_num; ++i) {
        range = &ports->ranges[i];
        if (range->beginning == 0 && range->ending == 0) {
            break;
        }
        range = NULL;
    }
    if (range == NULL) {
        ports->ranges = realloc(ports->ranges, (ports->ranges_num + 1) * sizeof(*ports->ranges));
        range = &ports->ranges[ports->ranges_num++];
    }
    range->beginning = beg;
    range->ending = end;
    if (beg == end) {
        DBG("[config] Port %hu added to list.", beg);
    } else {
        DBG("[config] Ports range %hu - %hu added to list.", beg, end);
    }
    return 0;
}
ATTR_HIDDEN
int conf_file_read_port(const char *val, const char *beg, const char *end)
{
    ssize_t len;
    char *pend;
    int ret;

    assert (val);
    assert (beg);
    assert (end);

    len = end - beg;
    if (len <= 0) {
        ERR("[config] No value on %zu position", beg - val);
        return -EINVAL;
    }
    char tmp_buf[len+1];
    strncpy(tmp_buf, beg, len);
    tmp_buf[len] = '\0';
    ret = strtol(tmp_buf, &pend, 10);
    if (*pend != '\0') {
        ERR("[config] Can not recognize `%s' on %zu position", tmp_buf,
                beg - val);
        return -EINVAL;
    }

    return ret;
}
ATTR_HIDDEN
int conf_file_set_port_list(const char *val, struct configuration *config)
{
	int ret;
    const char *comma_pos, *hyphen_pos, *pos = val;
    unsigned short beg, end;
    size_t vlen;
    size_t i, j;

    assert(val);
    assert(config);

    vlen = strlen(val);
    comma_pos = strchr(pos, ',');
    hyphen_pos = strchr(pos, '-');

    while (pos != NULL && *pos != '\0') {
        if (pos == comma_pos || pos == hyphen_pos) {
            ERR("[config] Invalid %s value for %s: unexpected `%c' on "
                    "%zu position", val, conf_port_list_str, *pos, pos - val);
            return -EINVAL;
        }
        if (comma_pos != NULL && (comma_pos < hyphen_pos || hyphen_pos == NULL)) {
            ret = conf_file_read_port(val, pos, comma_pos);
            if (ret <= 0) {
                ERR("[config] Invalid %s value for %s", val, conf_port_list_str);
                return -EINVAL;
            }
            beg = end = ret;
            pos = comma_pos + 1;
            if (pos < val + vlen) {
                comma_pos = strchr(pos, ',');
            } else {
                pos = NULL;
            }
        } else if (hyphen_pos != NULL){
            if (comma_pos == NULL) {
                comma_pos = val + vlen;
            }
            ret = conf_file_read_port(val, pos, hyphen_pos);
            if (ret <= 0) {
                ERR("[config] Invalid %s value for %s", val, conf_port_list_str);
                return -EINVAL;
            }
            beg = ret;
            ret = conf_file_read_port(val, hyphen_pos + 1, comma_pos);
            if (ret <= 0) {
                ERR("[config] Invalid %s value for %s", val, conf_port_list_str);
                return -EINVAL;
            }
            end = ret;
            pos = comma_pos + 1;
            if (pos < val + vlen) {
                comma_pos = strchr(pos, ',');
                hyphen_pos = strchr(pos, '-');
            } else {
                pos = NULL;
            }
        } else {
            ret = conf_file_read_port(val, pos, val + vlen);
            if (ret <= 0) {
                ERR("[config] Invalid %s value for %s", val, conf_port_list_str);
                return -EINVAL;
            }
            beg = end = ret;
            pos = NULL;
        }
        ret = conf_file_add_ports_range(&config->ports, beg, end);
        if (ret < 0) {
            ERR("[config] Invalid %s value for %s", val, conf_port_list_str);
            return ret;
        }
    }
    if (config->ports.ranges_num > 0) {
        DBG("[config] Ports ranges configured for %s %s",
               conf_port_list_str, val);
    } else {
        DBG("[config] No ports ranges configured for %s %s",
               conf_port_list_str, val);
    }
    for (i=0; i<config->ports.ranges_num; ++i) {
        beg = config->ports.ranges[i].beginning;
        end = config->ports.ranges[i].ending;
        if ( beg == 0 && end == 0) {
            for (j=i; j<config->ports.ranges_num - 1; ++j) {
                config->ports.ranges[j].beginning =
                    config->ports.ranges[j+1].beginning;
                config->ports.ranges[j].ending =
                    config->ports.ranges[j+1].ending;
            }
            --config->ports.ranges_num;
        } else if (beg == end) {
            DBG("[config]   %zu: %hu", i + 1, beg);
        } else {
            DBG("[config]   %zu: %hu - %hu", i + 1, beg, end);
        }
    }
    return 0;
}

/*
 * Applies the SOCKS authentication configuration and sets the final SOCKS
 * username and password.
 *
 * Return 0 if successful, and negative value on error.
 */
ATTR_HIDDEN
int conf_apply_socks_auth(struct configuration *config)
{
	int ret;
	pid_t pid;
	time_t now;

	assert(config);

	if (!config->socks5_use_auth && !config->isolate_pid) {
		/* No auth specified at all. */
		ret = 0;
		goto end;
	} else if (config->socks5_use_auth && !config->isolate_pid) {
		/* SOCKS5 auth specified by user, already setup. */
		ret = 0;
		goto end;
	} else if (config->socks5_use_auth && config->isolate_pid) {
		ERR("[config] %s and SOCKS5 auth both set.", conf_isolate_pid_str);
		ret = -EINVAL;
		goto end;
	}


	/* PID based isolation requested.
	 *   Username: 'torsocks-' PID ':' TIME
	 *   Password: '0'
	 */

	pid = getpid();
	now = time(NULL);

	ret = snprintf(config->conf_file.socks5_username,
			sizeof(config->conf_file.socks5_username), isolate_username_fmt,
			(long) pid, (long long int) now);
	if (ret < 0 || ret >= (int) sizeof(config->conf_file.socks5_username)) {
		ret = -ENOBUFS;
		goto end;
	}

	ret = snprintf(config->conf_file.socks5_password,
			sizeof(config->conf_file.socks5_password), "%s", isolate_password);
	if (ret < 0 || ret >= (int) sizeof(config->conf_file.socks5_password)) {
		ret = -ENOBUFS;
		goto end;
	}

	DBG("[config]: %s: '%s'/'%s'", conf_isolate_pid_str,
			config->conf_file.socks5_username,
			config->conf_file.socks5_password);

	config->socks5_use_auth = 1;
	ret = 0;

end:
	return ret;
}

/*
 * Read and populate the given config parsed data structure.
 *
 * Return 0 on success or else a negative value.
 */
ATTR_HIDDEN
int config_file_read(const char *filename, struct configuration *config)
{
	int ret;
	FILE *fp;

	assert(config);

	/* Clear out the structure */
	memset(config, 0x0, sizeof(*config));

	/* If a filename wasn't provided, use the default. */
	if (!filename) {
		filename = DEFAULT_CONF_FILE;
		DBG("Config file not provided by TORSOCKS_CONF_FILE. Using default %s",
				filename);
	}

	fp = fopen(filename, "r");
	if (!fp) {
		WARN("Config file not found: %s. Using default for Tor", filename);
		(void) conf_file_set_tor_address(DEFAULT_TOR_ADDRESS, config);
		/*
		 * We stringify the default value here so we can print the debug
		 * statement in the function call to set port.
		 */
		(void) conf_file_set_tor_port(XSTR(DEFAULT_TOR_PORT), config);

		ret = set_onion_info(
				DEFAULT_ONION_ADDR_RANGE "/" DEFAULT_ONION_ADDR_MASK, config);
		if (!ret) {
			/* ENOMEM is probably the only case here. */
			goto error;
		}

		config->allow_inbound = 0;
		goto end;
	}

	ret = parse_config_file(fp, config);
	if (ret < 0) {
		goto error;
	}

	DBG("Config file %s opened and parsed.", filename);

end:
error:
	if (fp) {
		fclose(fp);
	}
	return ret;
}

/*
 * Free everything inside a configuration file object. It is the caller
 * responsability to free the object if needed.
 */
ATTR_HIDDEN
void config_file_destroy(struct config_file *conf)
{
	assert(conf);

	free(conf->tor_address);
}
