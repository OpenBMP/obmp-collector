/*
 * Copyright (c) 2013-2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */
#include "UpdateMsg.h"

#include <string>
#include <cstring>
#include <sstream>

#include <arpa/inet.h>

#include "ExtCommunity.h"
#include "MPReachAttr.h"
#include "MPUnReachAttr.h"
#include "MPLinkStateAttr.h"

namespace bgp_msg {

/**
 * Constructor for class
 *
 * \details Handles bgp update messages
 *
 * \param [in]     logPtr           Pointer to existing Logger for app logging
 * \param [in]     pperAddr         Printed form of peer address used for logging
 * \param [in]     routerAddr       The router IP address - used for logging
 * \param [in,out] peer_info   Persistent peer information
 * \param [in]     enable_debug     Debug true to enable, false to disable
 */
UpdateMsg::UpdateMsg(Logger *logPtr, std::string peerAddr, std::string routerAddr, BMPReader::peer_info *peer_info,
                     bool enable_debug)
        : debug(enable_debug),
          logger(logPtr),
          peer_info(peer_info) {

    this->peer_addr = peerAddr;
    this->router_addr = routerAddr;

// BELOW check is not needed, but it's here as a reminder
//    if (peer_info->using_2_octet_asn)
//        four_octet_asn = false;
//    else

    four_octet_asn = peer_info->recv_four_octet_asn and peer_info->sent_four_octet_asn;
}

UpdateMsg::~UpdateMsg() {
}

/**
 * Parses the update message
 *
 * \details
 *      Reads the update message from socket and parses it.  The parsed output will
 *      be added to the DB.
 *
 * \param [in]   data           Pointer to raw bgp payload data, starting at the notification message
 * \param [in]   size           Size of the data available to read; prevent overrun when reading
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 *
 * \return ZERO is error, otherwise a positive value indicating the number of bytes read from update message
 */
size_t UpdateMsg::parseUpdateMsg(u_char *data, size_t size, parsed_update_data &parsed_data) {
    size_t      read_size       = 0;
    u_char      *bufPtr         = data;

    // Clear the parsed_data
    parsed_data.advertised.clear();
    parsed_data.attrs.clear();
    parsed_data.withdrawn.clear();


    /* ---------------------------------------------------------
     * Parse and setup the update header struct
     */
    update_bgp_hdr uHdr;

    SELF_DEBUG("%s: rtr=%s: Parsing update message of size %d", peer_addr.c_str(), router_addr.c_str(), size);

    if (size < 2) {
        LOG_WARN("%s: rtr=%s: Update message is too short to parse header", peer_addr.c_str(), router_addr.c_str());
        return 0;
    }

    // Get the withdrawn length
    memcpy(&uHdr.withdrawn_len, bufPtr, sizeof(uHdr.withdrawn_len));
    bufPtr += sizeof(uHdr.withdrawn_len); read_size += sizeof(uHdr.withdrawn_len);
    bgp::SWAP_BYTES(&uHdr.withdrawn_len);

    // Set the withdrawn data pointer
    if ((size - read_size) < uHdr.withdrawn_len) {
        LOG_WARN("%s: rtr=%s: Update message is too short to parse withdrawn data", peer_addr.c_str(), router_addr.c_str());
        return 0;
    }

    uHdr.withdrawnPtr = bufPtr;
    bufPtr += uHdr.withdrawn_len; read_size += uHdr.withdrawn_len;

    SELF_DEBUG("%s: rtr=%s: Withdrawn len = %hu", peer_addr.c_str(), router_addr.c_str(), uHdr.withdrawn_len );

    // Get the attributes length
    memcpy(&uHdr.attr_len, bufPtr, sizeof(uHdr.attr_len));
    bufPtr += sizeof(uHdr.attr_len); read_size += sizeof(uHdr.attr_len);
    bgp::SWAP_BYTES(&uHdr.attr_len);
    SELF_DEBUG("%s: rtr=%s: Attribute len = %hu", peer_addr.c_str(), router_addr.c_str(), uHdr.attr_len);

    // Set the attributes data pointer
    if ((size - read_size) < uHdr.attr_len) {
        LOG_WARN("%s: rtr=%s: Update message is too short to parse attr data", peer_addr.c_str(), router_addr.c_str());
        return 0;
    }
    uHdr.attrPtr = bufPtr;
    bufPtr += uHdr.attr_len; read_size += uHdr.attr_len;

    // Set the NLRI data pointer
    uHdr.nlriPtr = bufPtr;

    /*
     * Check if End-Of-RIB
     */
    if (not uHdr.withdrawn_len and (size - read_size) <= 0 and not uHdr.attr_len) {

	      peer_info->endOfRIB = true;		// Indicates End-of-RIB Marker received
        LOG_INFO("%s: rtr=%s: End-Of-RIB marker", peer_addr.c_str(), router_addr.c_str());

    } else {

        /* ---------------------------------------------------------
         * Parse the withdrawn prefixes
         */
        SELF_DEBUG("%s: rtr=%s: Getting the IPv4 withdrawn data", peer_addr.c_str(), router_addr.c_str());
        if (uHdr.withdrawn_len > 0)
            parseNlriData_v4(uHdr.withdrawnPtr, uHdr.withdrawn_len, parsed_data.withdrawn);


        /* ---------------------------------------------------------
         * Parse the attributes
         *      Handles MP_REACH/MP_UNREACH parsing as well
         */
        if (uHdr.attr_len > 0) {
            parseAttributes(uHdr.attrPtr, uHdr.attr_len, parsed_data);
        }

        /* ---------------------------------------------------------
         * Parse the NLRI data
         */
        SELF_DEBUG("%s: rtr=%s: Getting the IPv4 NLRI data, size = %d", peer_addr.c_str(), router_addr.c_str(), (size - read_size));
        if ((size - read_size) > 0) {
            parseNlriData_v4(uHdr.nlriPtr, (size - read_size), parsed_data.advertised);
            read_size = size;
        }
    }

    return read_size;
}

/**
 * Parses NLRI info (IPv4) from the BGP message
 *
 * \details
 *      Will get the NLRI and Withdrawn prefix entries from the data buffer.  As per RFC,
 *      this is only for v4.  V6/mpls is via mpbgp attributes (RFC4760)
 *
 * \param [in]   data       Pointer to the start of the prefixes to be parsed
 * \param [in]   len        Length of the data in bytes to be read
 * \param [out]  prefixes   Reference to a list<prefix_tuple> to be updated with entries
 */
void UpdateMsg::parseNlriData_v4(u_char *data, uint16_t len, std::list<bgp::prefix_tuple> &prefixes) {
    u_char       ipv4_raw[4];
    char         ipv4_char[16];
    u_char       addr_bytes;

    bgp::prefix_tuple tuple;

    if (len <= 0 or data == NULL)
        return;

    // TODO: Can extend this to support multicast, but right now we set it to unicast v4
    // Set the type for all to be unicast V4
    tuple.type = bgp::PREFIX_UNICAST_V4;
    tuple.isIPv4 = true;

    // Loop through all prefixes
    for (size_t read_size=0; read_size < len; read_size++) {

        bzero(ipv4_raw, sizeof(ipv4_raw));
        bzero(tuple.prefix_bin, sizeof(tuple.prefix_bin));

        // Parse add-paths if enabled
        if (peer_info->add_path_capability.isAddPathEnabled(bgp::BGP_AFI_IPV4, bgp::BGP_SAFI_UNICAST)
                and (len - read_size) >= 4) {
            memcpy(&tuple.path_id, data, 4);
            bgp::SWAP_BYTES(&tuple.path_id);
            data += 4; read_size += 4;
        } else
            tuple.path_id = 0;

        // set the address in bits length
        tuple.len = *data++;

        // Figure out how many bytes the bits requires
        addr_bytes = tuple.len / 8;
        if (tuple.len % 8)
            ++addr_bytes;

        SELF_DEBUG("%s: rtr=%s: Reading NLRI data prefix bits=%d bytes=%d", peer_addr.c_str(),
                    router_addr.c_str(), tuple.len, addr_bytes);

        if (addr_bytes <= 4) {
            memcpy(ipv4_raw, data, addr_bytes);
            read_size += addr_bytes;
            data += addr_bytes;

            // Convert the IP to string printed format
            inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
            tuple.prefix.assign(ipv4_char);
            SELF_DEBUG("%s: rtr=%s: Adding prefix %s len %d", peer_addr.c_str(),
                        router_addr.c_str(), ipv4_char, tuple.len);

            // set the raw/binary address
            memcpy(tuple.prefix_bin, ipv4_raw, sizeof(ipv4_raw));

            // Add tuple to prefix list
            prefixes.push_back(tuple);

        } else if (addr_bytes > 4) {
            LOG_NOTICE("%s: rtr=%s: NRLI v4 address is larger than 4 bytes bytes=%d len=%d",
                       peer_addr.c_str(), router_addr.c_str(), addr_bytes, tuple.len);
        }
    }
}

/**
 * Parses the BGP attributes in the update
 *
 * \details
 *     Parses all attributes.  Decoded values are updated in 'parsed_data'
 *
 * \param [in]   data       Pointer to the start of the prefixes to be parsed
 * \param [in]   len        Length of the data in bytes to be read
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void UpdateMsg::parseAttributes(u_char *data, uint16_t len, parsed_update_data &parsed_data) {
    /*
     * Per RFC4271 Section 4.3, flat indicates if the length is 1 or 2 octets
     */
    u_char   attr_flags;
    u_char   attr_type;
    uint16_t attr_len;

    if (len == 0)
        return;

    else if (len < 3) {
        LOG_WARN("%s: rtr=%s: Cannot parse the attributes due to the data being too short, error in update message. len=%d",
                peer_addr.c_str(), router_addr.c_str(), len);
        return;
    }

    /*
     * Iterate through all attributes and parse them
     */
    for (int read_size=0;  read_size < len; read_size += 2) {
        attr_flags = *data++;
        attr_type = *data++;

        // Check if the length field is 1 or two bytes
        if (ATTR_FLAG_EXTENDED(attr_flags)) {
            SELF_DEBUG("%s: rtr=%s: extended length path attribute bit set for an entry", peer_addr.c_str(), router_addr.c_str());

            memcpy(&attr_len, data, 2); data += 2; read_size += 2;
            bgp::SWAP_BYTES(&attr_len);

        } else {
            attr_len = *data++;
            read_size++;
        }

        SELF_DEBUG("%s: rtr=%s: attribute type = %d len_sz = %d",
                peer_addr.c_str(), router_addr.c_str(), attr_type, attr_len);

        // Get the attribute data, if we have any; making sure to not overrun buffer
        if (attr_len > 0 and (read_size + attr_len) <= len ) {
            // Data pointer is currently at the data position of the attribute

            /*
             * Parse data based on attribute type
             */
            parseAttrData(attr_type, attr_len, data, parsed_data);
            data        += attr_len;
            read_size   += attr_len;

            SELF_DEBUG("%s: rtr=%s: parsed attr type=%d, size=%hu", peer_addr.c_str(), router_addr.c_str(),
                        attr_type, attr_len);

        } else if (attr_len) {
            LOG_NOTICE("%s: rtr=%s: Attribute data len of %hu is larger than available data in update message of %hu",
                    peer_addr.c_str(), router_addr.c_str(), attr_len, (len - read_size));
            return;
        }
    }

}

/**
 * Parse attribute data based on attribute type
 *
 * \details
 *      Parses the attribute data based on the passed attribute type.
 *      Parsed_data will be updated based on the attribute data parsed.
 *
 * \param [in]   attr_type      Attribute type
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  parsed_data    Reference to parsed_update_data; will be updated with all parsed data
 */
void UpdateMsg::parseAttrData(u_char attr_type, uint16_t attr_len, u_char *data, parsed_update_data &parsed_data) {
    std::string decodeStr       = "";
    u_char      ipv4_raw[4];
    char        ipv4_char[16];
    uint32_t    value32bit;
    uint16_t    value16bit;

    /*
     * Parse based on attribute type
     */
    switch (attr_type) {

        case ATTR_TYPE_ORIGIN : // Origin
            switch (data[0]) {
               case 0 : decodeStr.assign("igp"); break;
               case 1 : decodeStr.assign("egp"); break;
               case 2 : decodeStr.assign("incomplete"); break;
            }

            parsed_data.attrs[ATTR_TYPE_ORIGIN] = decodeStr;
            break;

        case ATTR_TYPE_AS_PATH : // AS_PATH
            parseAttr_AsPath(attr_len, data, parsed_data.attrs);
            break;

        case ATTR_TYPE_NEXT_HOP : // Next hop v4
            memcpy(ipv4_raw, data, 4);
            inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
            parsed_data.attrs[ATTR_TYPE_NEXT_HOP] = std::string(ipv4_char);
            break;

        case ATTR_TYPE_MED : // MED value
        {
            memcpy(&value32bit, data, 4);
            bgp::SWAP_BYTES(&value32bit);
            std::ostringstream numString;
            numString << value32bit;
            parsed_data.attrs[ATTR_TYPE_MED] = numString.str();
            break;
        }
        case ATTR_TYPE_LOCAL_PREF : // local pref value
        {
            memcpy(&value32bit, data, 4);
            bgp::SWAP_BYTES(&value32bit);
            std::ostringstream numString;
            numString << value32bit;
            parsed_data.attrs[ATTR_TYPE_LOCAL_PREF] = numString.str();
            break;
        }
        case ATTR_TYPE_ATOMIC_AGGREGATE : // Atomic aggregate
            parsed_data.attrs[ATTR_TYPE_ATOMIC_AGGREGATE] = std::string("1");
            break;

        case ATTR_TYPE_AGGEGATOR : // Aggregator
            parseAttr_Aggegator(attr_len, data, parsed_data.attrs);
            break;

        case ATTR_TYPE_ORIGINATOR_ID : // Originator ID
            memcpy(ipv4_raw, data, 4);
            inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
            parsed_data.attrs[ATTR_TYPE_ORIGINATOR_ID] = std::string(ipv4_char);
            break;

        case ATTR_TYPE_CLUSTER_LIST : // Cluster List (RFC 4456)
            // According to RFC 4456, the value is a sequence of cluster id's
            for (int i=0; i < attr_len; i += 4) {
                memcpy(ipv4_raw, data, 4);
                data += 4;
                inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
                decodeStr.append(ipv4_char);
                decodeStr.append(" ");
            }

            parsed_data.attrs[ATTR_TYPE_CLUSTER_LIST] = decodeStr;
            break;

        case ATTR_TYPE_COMMUNITIES : // Community list
        {
            for (int i = 0; i < attr_len; i += 4) {
                std::ostringstream numString;

                // Add space between entries
                if (i)
                    decodeStr.append(" ");

                // Add entry
                memcpy(&value16bit, data, 2);
                data += 2;
                bgp::SWAP_BYTES(&value16bit);
                numString << value16bit;
                numString << ":";

                memcpy(&value16bit, data, 2);
                data += 2;
                bgp::SWAP_BYTES(&value16bit);
                numString << value16bit;
                decodeStr.append(numString.str());
            }

            parsed_data.attrs[ATTR_TYPE_COMMUNITIES] = decodeStr;

            break;
        }
        case ATTR_TYPE_EXT_COMMUNITY : // extended community list (RFC 4360)
        {
            ExtCommunity ec(logger, peer_addr, debug);
            ec.parseExtCommunities(attr_len, data, parsed_data);
            break;
        }

        case ATTR_TYPE_IPV6_EXT_COMMUNITY : // IPv6 specific extended community list (RFC 5701)
        {
            ExtCommunity ec6(logger, peer_addr, debug);
            ec6.parsev6ExtCommunities(attr_len, data, parsed_data);
            break;
        }

        case ATTR_TYPE_MP_REACH_NLRI :  // RFC4760
        {
            MPReachAttr mp(logger, peer_addr, peer_info, debug);
            mp.parseReachNlriAttr(attr_len, data, parsed_data);
            break;
        }

        case ATTR_TYPE_MP_UNREACH_NLRI : // RFC4760
        {
            MPUnReachAttr mp(logger, peer_addr, peer_info, debug);
            mp.parseUnReachNlriAttr(attr_len, data, parsed_data);
            break;
        }

        case ATTR_TYPE_AS_PATHLIMIT : // deprecated
        {
            break;
        }

        case ATTR_TYPE_BGP_LS:
        {
            MPLinkStateAttr ls(logger, peer_addr, &parsed_data, debug);
            ls.parseAttrLinkState(attr_len, data);
            break;
        }

        case ATTR_TYPE_AS4_PATH:
        {
            SELF_DEBUG("%s: rtr=%s: attribute type AS4_PATH is not yet implemented, skipping for now.",
                     peer_addr.c_str(), router_addr.c_str());
            break;
        }

        case ATTR_TYPE_AS4_AGGREGATOR:
        {
            SELF_DEBUG("%s: rtr=%s: attribute type AS4_AGGREGATOR is not yet implemented, skipping for now.",
                       peer_addr.c_str(), router_addr.c_str());
            break;
        }

        case ATTR_TYPE_LARGE_COMMUNITY: {
            // RFC8092
            if (attr_len >= 12) {
                for (int i = 0; i < attr_len; i += 12) {
                    std::ostringstream numString;

                    // Add space between entries
                    if (i)
                        decodeStr.append(" ");

                    // Global Administrator
                    memcpy(&value32bit, data, 4);
                    data += 4;
                    bgp::SWAP_BYTES(&value32bit);
                    numString << value32bit;
                    numString << ":";

                    // Local Data Part 1
                    memcpy(&value32bit, data, 4);
                    data += 4;
                    bgp::SWAP_BYTES(&value32bit);
                    numString << value32bit;
                    numString << ":";

                    // Local Data Part 2
                    memcpy(&value32bit, data, 4);
                    data += 4;
                    bgp::SWAP_BYTES(&value32bit);
                    numString << value32bit;

                    decodeStr.append(numString.str());
                }

                parsed_data.attrs[ATTR_TYPE_LARGE_COMMUNITY] = decodeStr;
            }

            break;
        }

        default:
            SELF_DEBUG("%s: rtr=%s: attribute type %d is not yet implemented or intentionally ignored, skipping for now.",
                    peer_addr.c_str(), router_addr.c_str(), attr_type);
            break;

    } // END OF SWITCH ATTR TYPE
}

/**
 * Parse attribute AGGEGATOR data
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  attrs          Reference to the parsed attr map - will be updated
 */
void UpdateMsg::parseAttr_Aggegator(uint16_t attr_len, u_char *data, parsed_attrs_map &attrs) {
    std::string decodeStr;
    uint32_t    value32bit = 0;
    uint16_t    value16bit = 0;
    u_char      ipv4_raw[4];
    char        ipv4_char[16];

    // If using RFC6793, the len will be 8 instead of 6
     if (attr_len == 8) { // RFC6793 ASN of 4 octets
         memcpy(&value32bit, data, 4); data += 4;
         bgp::SWAP_BYTES(&value32bit);
         std::ostringstream numString;
         numString << value32bit;
         decodeStr.assign(numString.str());

     } else if (attr_len == 6) {
         memcpy(&value16bit, data, 2); data += 2;
         bgp::SWAP_BYTES(&value16bit);
         std::ostringstream numString;
         numString << value16bit;
         decodeStr.assign(numString.str());

     } else {
         LOG_ERR("%s: rtr=%s: path attribute is not the correct size of 6 or 8 octets.", peer_addr.c_str(), router_addr.c_str());
         return;
     }

     decodeStr.append(" ");
     memcpy(ipv4_raw, data, 4);
     inet_ntop(AF_INET, ipv4_raw, ipv4_char, sizeof(ipv4_char));
     decodeStr.append(ipv4_char);

     attrs[ATTR_TYPE_AGGEGATOR] = decodeStr;
}

/**
 * Parse attribute AS_PATH data
 *
 * \param [in]   attr_len       Length of the attribute data
 * \param [in]   data           Pointer to the attribute data
 * \param [out]  attrs          Reference to the parsed attr map - will be updated
 */
void UpdateMsg::parseAttr_AsPath(uint16_t attr_len, u_char *data, parsed_attrs_map &attrs) {
    std::string decoded_path;
    int         path_len    = attr_len;
    uint16_t    as_path_cnt = 0;

    u_char      seg_type;
    u_char      seg_len;
    uint32_t    seg_asn = 0;

    u_char *data_ptr = data;

    /*
     * We first must try to parse using four octet since the RFC says that the peer header
     *     defines the encoding and not the capabilities.  four_octet_asn represents
     *     the capabilities only.
     */
    char asn_octet_size = (peer_info->using_2_octet_asn /* and not four_octet_asn */) ? 2 : 4;

    if (path_len < asn_octet_size) // Nothing to parse if length doesn't include at least one asn
        return;

    /*
     * Loop through each path segment
     */
    while (path_len > 0) {

        seg_type = *data++;
        seg_len  = *data++;                  // Count of AS's, not bytes
        path_len -= 2;

        if (seg_type == 1) {                 // If AS-SET open with a brace
            decoded_path.append(" {");
        }

        SELF_DEBUG("%s: rtr=%s: as_path seg_len = %d seg_type = %d, path_len = %d total_len = %d as_octet_size = %d",
                   peer_addr.c_str(), router_addr.c_str(),
                   seg_len, seg_type, path_len, attr_len, asn_octet_size);

        if ((seg_len * asn_octet_size) > path_len){

            LOG_NOTICE("%s: rtr=%s: Could not parse the AS PATH due to update message buffer being too short when using ASN octet size %d (%d > %d)",
                       peer_addr.c_str(), router_addr.c_str(), asn_octet_size, (seg_len * asn_octet_size), path_len);

            if (not peer_info->using_2_octet_asn) {
                LOG_NOTICE("%s: rtr=%s: switching encoding size to 2-octet",
                           peer_addr.c_str(), router_addr.c_str());

                peer_info->using_2_octet_asn = true;

                parseAttr_AsPath(attr_len, data_ptr, attrs);
            }
            return;
        }

        // The rest of the data is the as path sequence, in blocks of 2 or 4 bytes
        for (; seg_len > 0; seg_len--) {
            seg_asn = 0;
            memcpy(&seg_asn, data, asn_octet_size);  data += asn_octet_size;
            path_len -= asn_octet_size;                               // Adjust the path length for what was read

            bgp::SWAP_BYTES(&seg_asn, asn_octet_size);
            decoded_path.append(" ");
            std::ostringstream numString;
            numString << seg_asn;
            decoded_path.append(numString.str());

            // Increase the as path count
            ++as_path_cnt;
        }

        if (seg_type == 1) {            // If AS-SET close with a brace
            decoded_path.append(" }");
        }
    }

    SELF_DEBUG("%s: rtr=%s: Parsed AS_PATH count %hu : %s", peer_addr.c_str(), router_addr.c_str(), as_path_cnt, decoded_path.c_str());

    /*
     * Update the attributes map
     */
    attrs[ATTR_TYPE_AS_PATH] = decoded_path;

    {
        std::ostringstream numString;
        numString << as_path_cnt;
        attrs[ATTR_TYPE_INTERNAL_AS_COUNT] = numString.str();
    }

    /*
     * Get the last ASN and update the attributes map
     */
    {
        std::ostringstream numString;
        numString << seg_asn;
        attrs[ATTR_TYPE_INTERNAL_AS_ORIGIN] = numString.str();
    }

}

} /* namespace bgp_msg */
