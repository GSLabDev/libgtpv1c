/*
 * Copyright (c) 2022 Great Software Laboratory (GS Lab)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */

#ifndef __GTPV1_IES_H__
#define __GTPV1_IES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define CHAR_SIZE 8
#define APN_LEN 128
#define QOS_BUFF_SIZE 248
#define TFT_BUFF_SIZE 1024
#define ADDRESS_LEN 16
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16
#define PROTOCOL_CONFIG_LENGTH 256
#define PRIVATE_EXTENSION_LEN 10
#define TRIGGER_ID_LEN 10
#define OMC_IDENTITY_LEN 10
#define GEO_LOCATION_LEN 10
#define CAMEL_INFO_PDP_IE_LEN 10
#define MSISDN_LEN 10
#define SGSN_NUMBER_LENGTH 256
#define FQDN_LENGTH 256
#define UE_NETWORK_CAPABILITY_LEN 256
#define LHN_ID_LEN 256
#define RAN_LEN 256
#define RIM_LEN 256
#define BSS_LEN 256
#define STN_SR_LEN 256
#define C_MSISDN_LEN 16
#define PFCS_LEN 256
#define XID_LEN 128
#define RAND_LEN 16
#define CK_LEN 16
#define IK_LEN 16
#define RRC_LEN 256
#define MAX_EXT_TYPE_LIST 16
#define SCEF_ID_LEN 64
#define AUTH_TRIPLET_SIZE 512
#define QUINTIPLET_SIZE 512
#define CONT_LEN 512
#define NODE_LEN 256
#define PCO_LEN 253
#define CONTENT_LEN 255
#define MS_LEN 256
#define SIZE 4096

/*
 *  @brief : enum to store IE types 
 */
enum IE_TYPE {
	GTPV1_IE_CAUSE = 1,
	GTPV1_IE_IMSI,
	GTPV1_IE_ROUTEING_AREA_IDENTITY,
	GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER,
	GTPV1_IE_PACKET_TMSI,
	GTPV1_IE_REORDERING_REQ = 8,
	GTPV1_IE_AUTH_TRIPLET,
	GTPV1_IE_MAP_CAUSE = 11,
	GTPV1_IE_P_TMSI_SIGNATURE,
	GTPV1_IE_MS_VALIDATED,
	GTPV1_IE_RECOVERY,
	GTPV1_IE_SELECTION_MODE,
	GTPV1_IE_TEID_DATA_1,
	GTPV1_IE_TEID_CONTROL_PLANE,
	GTPV1_IE_TEID_DATA_2,
	GTPV1_IE_TEARDOWN_IND,
	GTPV1_IE_NSAPI,
	GTPV1_IE_RANAP_CAUSE,
	GTPV1_IE_RAB_CONTEXT,
	GTPV1_IE_RADIO_PRIORITY_SMS,
	GTPV1_IE_RADIO_PRIORITY,
	GTPV1_IE_PACKET_FLOW_ID,
	GTPV1_IE_CHRGNG_CHAR,
	GTPV1_IE_TRACE_REFERENCE,
	GTPV1_IE_TRACE_TYPE,
	GTPV1_IE_MS_NOT_RECHABLE_REASON,
	GTPV1_IE_CHARGING_ID = 127,
	GTPV1_IE_END_USER_ADDR,
	GTPV1_IE_MM_CONTEXT,
	GTPV1_IE_PDP_CONTEXT,	
	GTPV1_IE_APN,
	GTPV1_IE_PROTOCOL_CONFIG_OPTIONS,	
	GTPV1_IE_GSN_ADDR,
	GTPV1_IE_MSISDN,
	GTPV1_IE_QOS,
	GTPV1_IE_AUTH_QUINTUPLET,
	GTPV1_IE_TFT,
	GTPV1_IE_TARGET_IDENTIFICATION,
	GTPV1_IE_UTRAN_TRANSPARENT_CONTAINER,
	GTPV1_IE_RAB_SETUP_INFO,
	GTPV1_IE_EXTENSION_HEADER_TYPE_LIST,
	GTPV1_IE_TRIGGER_ID,
	GTPV1_IE_OMC_IDENTITY,
	GTPV1_IE_RAN_TRANSPARENT_CONTAINER,
	GTPV1_IE_PDP_CONTEXT_PRIORITIZATION,
	GTPV1_IE_ADDITIONAL_RAB_SETUP_INFO,
	GTPV1_IE_SGSN_NUMBER,
	GTPV1_IE_COMMON_FLAG,
	GTPV1_IE_APN_RESTRICTION,
	GTPV1_IE_RADIO_PRIORITY_LCS,
	GTPV1_IE_RAT_TYPE, 
	GTPV1_IE_USER_LOCATION_INFORMATION,
	GTPV1_IE_MS_TIME_ZONE,
	GTPV1_IE_IMEI_SV,
	GTPV1_IE_CAMEL_CHARGING_INFORMATION_CONTAINER,
	GTPV1_IE_MBMS_UE_CONTEXT,
	GTPV1_IE_RIM_ROUTING_ADDR = 158,
	GTPV1_IE_MBMS_PROTOCOL_CONFIG_OPTIONS,
	GTPV1_IE_SRC_RNC_PDCP_CTXT_INFO = 161,
	GTPV1_IE_ADDITIONAL_TRACE_INFORMATION,
	GTPV1_IE_HOP_COUNTER,
	GTPV1_IE_SELECTED_PLMN_ID,
	GTPV1_IE_BSS_CONTAINER = 173,
	GTPV1_IE_CELL_IDENTIFICATION,
	GTPV1_IE_PDU_NUMBERS,
	GTPV1_IE_BSSGP_CAUSE,
	GTPV1_IE_RIM_ROUTING_ADDR_DISCRIMINATOR = 178,
	GTPV1_IE_LIST_OF_SET_UP_PFCS,
	GTPV1_IE_PS_HANDOVER_XID_PARAM,
	GTPV1_IE_MS_INFO_CHANGE_REPORTING_ACTION,
	GTPV1_IE_DIRECT_TUNNEL_FLAG,
	GTPV1_IE_CORRELATION_ID,
	GTPV1_IE_BEARER_CONTROL_MODE,
	GTPV1_IE_RELIABLE_INTER_RAT_HANDOVER_INFO = 188,
	GTPV1_IE_RFSP_INDEX,
	GTPV1_IE_FQDN,
	GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_I,
	GTPV1_IE_EVOLVED_ALLOCATION_RETENTION_PRIORITY_II,
	GTPV1_IE_EXTENDED_COMMON_FLAG,
	GTPV1_IE_USER_CSG_INFORMATION,
	GTPV1_IE_CSG_INFORMATION_REPORTING_ACTION,
	GTPV1_IE_CSG_ID,
	GTPV1_IE_CSG_MEMB_INDCTN,
	GTPV1_IE_APN_AMBR,
	GTPV1_IE_UE_NETWORK_CAPABILITY,
	GTPV1_IE_UE_AMBR,
	GTPV1_IE_APN_AMBR_WITH_NSAPI,
	GTPV1_IE_GGSN_BACK_OFF_TIME,
	GTPV1_IE_SIGNALLING_PRIORITY_INDICATION,
	GTPV1_IE_SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI,
	GTPV1_IE_HIGER_BITRATES_THAN_16_MBPS_FLAG,
	GTPV1_IE_ADDTL_MM_CTXT_SRVCC = 207,
	GTPV1_IE_ADDTL_FLGS_SRVCC,
	GTPV1_IE_STN_SR,
	GTPV1_IE_C_MSISDN,
	GTPV1_IE_EXTENDED_RANAP_CAUSE,
	GTPV1_IE_ENODEB_ID,
	GTPV1_IE_SELECTION_MODE_WITH_NSAPI,
	GTPV1_IE_ULI_TIMESTAMP,
	GTPV1_IE_LOCAL_HOME_NETWORK_ID_WITH_NSAPI,
	GTPV1_IE_CN_OPERATOR_SELECTION_ENTITY,
	GTPV1_IE_UE_USAGE_TYPE,
	GTPV1_IE_EXTENDED_COMMON_FLAGS_II,
	GTPV1_IE_NODE_IDENTIFIER,
	GTPV1_IE_UE_SCEF_PDN_CONNTECTION = 221,
	GTPV1_IE_IOV_UPDATES_COUNTER,
	GTPV1_IE_MAPPED_UE_USAGE_TYPE,
	GTPV1_IE_UP_FUNCTION_SELECTION_INDICATION,
	GTPV1_IE_CHARGING_GATEWAY_ADDR = 251,
	GTPV1_IE_PRIVATE_EXTENSION = 255
};

/*
 *  @brief : enum to store TV type IE length
 */
enum IE_LENGTH {
	GTPV1_IE_CAUSE_LEN = 1,
	GTPV1_IE_IMSI_LEN = 8,
	GTPV1_IE_ROUTEING_AREA_IDENTITY_LEN = 6,
	GTPV1_IE_TEMPORARY_LOGICAL_LINK_IDENTIFIER_LEN = 4,
	GTPV1_IE_PACKET_TMSI_LEN = 4,
	GTPV1_IE_REORDERING_REQ_LEN = 1,
	GTPV1_IE_AUTH_TRIPLET_LEN = 28,
	GTPV1_IE_MAP_CAUSE_LEN = 1,
	GTPV1_IE_P_TMSI_SIGNATURE_LEN = 3,
	GTPV1_IE_MS_VALIDATED_LEN = 1,
	GTPV1_IE_RECOVERY_LEN = 1,
	GTPV1_IE_SELECTION_MODE_LEN = 1,
	GTPV1_IE_TEID_DATA_1_LEN = 4,
	GTPV1_IE_TEID_CONTROL_PLANE_LEN = 4,
	GTPV1_IE_TEID_DATA_2_LEN,
	GTPV1_IE_TEARDOWN_IND_LEN = 1,
	GTPV1_IE_NSAPI_LEN = 1,
	GTPV1_IE_RANAP_CAUSE_LEN = 1,
	GTPV1_IE_RAB_CONTEXT_LEN = 9,
	GTPV1_IE_RADIO_PRIORITY_SMS_LEN = 1,
	GTPV1_IE_RADIO_PRIORITY_LEN = 1,
	GTPV1_IE_PACKET_FLOW_ID_LEN,
	GTPV1_IE_CHRGNG_CHAR_LEN = 2,
	GTPV1_IE_TRACE_REFERENCE_LEN = 2,
	GTPV1_IE_TRACE_TYPE_LEN = 2,
	GTPV1_IE_MS_NOT_RECHABLE_REASON_LEN = 1,
	GTPV1_IE_CHARGING_ID_LEN = 4
};

/*
 *  @brief : structure for gtpv1 Header
 */
typedef struct gtpv1_header_t{
	uint8_t version :3;
	uint8_t protocol_type :1;
	uint8_t spare :1;  
	uint8_t extension_header :1;
	uint8_t seq_num_flag :1;
	uint8_t n_pdu_flag :1;
	uint8_t message_type;
	uint16_t message_len;
	uint32_t teid;
	uint16_t seq;
	uint8_t n_pdu_number;
	uint8_t next_extension_header_type;
}gtpv1_header_t;

/*
 *  @brief : structure for gtpv1 IE Header 
 */
typedef struct gtpv1_ie_header_t {
	uint8_t type;
	uint16_t length;
} gtpv1_ie_header_t;

/*
 *  @brief : structure for gtpv1 digits 
 */
typedef struct gtpv1_digits_t {
	uint8_t digit1:4;
	uint8_t digit2:4;
} gtpv1_digits_t;

/*
 *  @brief : structure of gtpv1 cause IE
 */
typedef struct gtpv1_cause_ie_t {
	gtpv1_ie_header_t header; /* type = 1 */
	uint8_t cause_value;
} gtpv1_cause_ie_t;

/*
 *  @brief : structure of gtpv1 IMSI IE
 */
typedef struct gtpv1_imsi_ie_t {
	gtpv1_ie_header_t header; /* type = 2 */
	uint64_t imsi_number_digits;
} gtpv1_imsi_ie_t;

/*
 *  @brief : structure for routing area identity
 */
typedef struct gtpv1_routing_area_identity_value_t {
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
	uint8_t mnc_digit_1 :4;
	uint16_t lac;
	uint8_t rac;
} gtpv1_routing_area_identity_value_t;

/*
 *  @brief : structure for routing area identity IE 
 */
typedef struct gtpv1_routing_area_identity_ie_t  {
	gtpv1_ie_header_t header; /* type = 3 */
	gtpv1_routing_area_identity_value_t rai_value;
} gtpv1_routing_area_identity_ie_t;

/*
 *  @brief : structure for temporary logical link identifier IE 
 */
typedef struct gtpv1_temporary_logical_link_identifier_ie_t {
	gtpv1_ie_header_t header; /* type = 4 */
	uint32_t tlli;
} gtpv1_temporary_logical_link_identifier_ie_t;

/*
 *  @brief : structure for packet tmsi IE 
 */
typedef struct gtpv1_packet_tmsi_ie_t {
	gtpv1_ie_header_t header; /* type = 5 */
	uint32_t p_tmsi;
} gtpv1_packet_tmsi_ie_t;

/*
 *  @brief : structure for reordering request IE 
 */
typedef struct gtpv1_reordering_req_ie_t {
	gtpv1_ie_header_t header; /* type = 8 */
	uint8_t spare :7;
	uint8_t reord_req :1;
} gtpv1_reordering_req_ie_t;

/*
 * @breif : structure for auth_triplet_value
 */
typedef struct gtpv1_auth_triplet_value_t {
	uint8_t rand[RAND_LEN];
	uint32_t sres;
	uint64_t kc;
} gtpv1_auth_triplet_value_t;

/*
 *  @brief : structure for auth triplet IE
 */
typedef struct gtpv1_auth_triplet_ie_t {
	gtpv1_ie_header_t header; /* type = 9 */
	gtpv1_auth_triplet_value_t auth_triplet_value;
} gtpv1_auth_triplet_ie_t;

/*
 *  @brief : structure for map cause IE
 */
typedef struct gtpv1_map_cause_ie_t {
	gtpv1_ie_header_t header; /* type = 11 */
	uint8_t map_cause_value;
} gtpv1_map_cause_ie_t;

/*
 *  @brief : structure for p tmsi signature IE 
 */
typedef struct gtpv1_p_tmsi_signature_ie_t {
	gtpv1_ie_header_t header; /* type = 12 */
	uint32_t p_tmsi_signature :24;
} gtpv1_p_tmsi_signature_ie_t;

/*
 *  @brief : structure for ms validated IE
 */
typedef struct gtpv1_ms_validated_ie_t {
	gtpv1_ie_header_t header; /* type = 13 */
	uint8_t spare :7;
	uint8_t ms_validated :1;
} gtpv1_ms_validated_ie_t;

/*
 *  @brief : structure for recovery IE
 */
typedef struct gtpv1_recovery_ie_t {
	gtpv1_ie_header_t header; /* type = 14 */
	uint8_t restart_counter;
} gtpv1_recovery_ie_t;

/*
 *  @brief : structure for selection mode IE 
 */
typedef struct gtpv1_selection_mode_ie_t {
	gtpv1_ie_header_t header; /* type = 15 */
	uint8_t spare2 :6;
	uint8_t selec_mode :2;
} gtpv1_selection_mode_ie_t;

/*
 *  @brief : structure for teid data 1, control plane IE
 */
typedef struct gtpv1_teid_ie_t {
	gtpv1_ie_header_t header; /* type = 16,17 */
	uint32_t teid;
} gtpv1_teid_ie_t;

/*
 *  @brief : structure for teid data 2 IE
 */
typedef struct gtpv1_teid_data_2_ie_t {
	gtpv1_ie_header_t header; /* type = 18 */
	uint8_t spare:4;
	uint8_t nsapi:4;
	uint32_t teid;
} gtpv1_teid_data_2_ie_t;

/*
 *  @brief : structure for teardown indication IE
 */
typedef struct gtpv1_teardown_ind_ie_t {
	gtpv1_ie_header_t header; /* type = 19 */
	uint8_t spare :7;
	uint8_t teardown_ind :1;
} gtpv1_teardown_ind_ie_t;

/*
 *  @brief : structure for nsapi IE
 */
typedef struct gtpv1_nsapi_ie_t {
	gtpv1_ie_header_t header; /* type = 20 */
	uint8_t spare :4;
	uint8_t nsapi_value :4;
} gtpv1_nsapi_ie_t;

/*
 *  @brief : structure for ranap cause IE
 */
typedef struct gtpv1_ranap_cause_ie_t {
	gtpv1_ie_header_t header; /* type = 21 */
	uint8_t ranap_cause;
} gtpv1_ranap_cause_ie_t;

/*
 *  @brief : structure for rab context IE
 */
typedef struct gtpv1_rab_context_ie_t {
	gtpv1_ie_header_t header; /* type = 22 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint16_t dl_gtp_u_sequence_number;
	uint16_t ul_gtp_u_sequence_number;
	uint16_t dl_pdcp_sequence_number;
	uint16_t ul_pdcp_sequence_number;
} gtpv1_rab_context_ie_t;

/*
 *  @brief : structure for radio priority sms IE
 */
typedef struct gtpv1_radio_priority_sms_ie_t {
	gtpv1_ie_header_t header; /* type = 23 */
	uint8_t spare :5;
	uint8_t radio_priority_sms :3;
} gtpv1_radio_priority_sms_ie_t;

/*
 *  @brief : structure for radio priority IE
 */
typedef struct gtpv1_radio_priority_ie_t {
	gtpv1_ie_header_t header; /* type = 24 */
	uint8_t nsapi :4;
	uint8_t spare :1;
	uint8_t radio_priority:3;
} gtpv1_radio_priority_ie_t ;

/*
 *  @brief : structure for packet flow ID IE
 */
typedef struct gtpv1_packet_flow_id_ie_t {
	gtpv1_ie_header_t header; /* type = 25 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint8_t packet_flow_id;
} gtpv1_packet_flow_id_ie_t ;

/*
 *  @brief : structure for charging characteristics IE
 */
typedef struct gtpv1_chrgng_char_ie_t {
	gtpv1_ie_header_t header; /* type = 26 */
	uint16_t chrgng_char_val;
} gtpv1_chrgng_char_ie_t;

/*
 *  @brief : structure for trace reference IE
 */
typedef struct gtpv1_trace_reference_ie_t {
	gtpv1_ie_header_t header; /* type = 27 */
	uint16_t trace_reference;
} gtpv1_trace_reference_ie_t;

/*
 *  @brief : structure for trace type IE
 */
typedef struct gtpv1_trace_type_ie_t {
	gtpv1_ie_header_t header; /* type = 28 */
	uint16_t trace_type;
} gtpv1_trace_type_ie_t;

/*
 *  @brief : structure for ms not rechable reason IE
 */
typedef struct gtpv1_ms_not_rechable_reason_ie_t {
	gtpv1_ie_header_t header; /* type = 29 */
	uint8_t reason_for_absence;
} gtpv1_ms_not_rechable_reason_ie_t;

/*
 *  @brief : structure for charging ID IE
 */
typedef struct gtpv1_charging_id_ie_t {
	gtpv1_ie_header_t header; /* type = 127 */
	uint32_t chrgng_id_val;
} gtpv1_charging_id_ie_t;

/*
 *  @brief : structure for pdp address
 */
typedef struct gtpv1_pdp_addr_t {
	uint32_t ipv4;
	uint8_t ipv6[IPV6_ADDR_LEN];
} gtpv1_pdp_addr_t;

/*
 *  @brief : structure for end user address IE
 */
typedef struct gtpv1_end_user_address_ie_t {
	gtpv1_ie_header_t header; /* type = 128 */
	uint8_t spare :4;
	uint8_t pdp_type_org :4;
	uint8_t pdp_type_number;
	gtpv1_pdp_addr_t pdp_address;
} gtpv1_end_user_address_ie_t;

/*
 *  @brief : structure for auth_quintuplet_value
 */
typedef struct gtpv1_auth_quintuplet_value_t {
	uint8_t rand[RAND_LEN];
	uint8_t xres_length;
	uint8_t xres[MS_LEN];
	uint8_t ck[CK_LEN];
	uint8_t ik[IK_LEN];
	uint8_t autn_length;
	uint8_t autn[MS_LEN];
} gtpv1_auth_quintuplet_value_t;

/*
 *  @brief : structure for auth quintuplet IE
 */
typedef struct gtpv1_auth_quintuplet_ie_t {
	gtpv1_ie_header_t header; /* type = 136 */
	gtpv1_auth_quintuplet_value_t auth_quintuplet_value;
} gtpv1_auth_quintuplet_ie_t;

/*
 *  @brief : structure for gsm key and triplet IE
 */
typedef struct gtpv1_gsm_key_and_triplet_t {
	uint8_t spare :5; //set as 1111
	uint8_t cksn :3;
	uint8_t no_of_vectors :3;
	uint8_t used_cipher :3;
	uint64_t kc;
	gtpv1_auth_triplet_value_t triplet[AUTH_TRIPLET_SIZE];
} gtpv1_gsm_key_and_triplet_t;

/*
 *  @brief : structure for umts keys and quintuplets IE
 */
typedef struct gtpv1_umts_keys_and_quintuplets_t {	
	uint8_t gupii :1;
	uint8_t ugipai :1;
	uint8_t used_gprs_integrity_protection_algo :3;
	uint8_t ksi :3;
	uint8_t no_of_vectors :3;
	uint8_t spare :3;  //spare 111
	uint8_t ck[CK_LEN];
	uint8_t ik[IK_LEN];
	uint16_t quintuplet_length;
	gtpv1_auth_quintuplet_value_t quintuplet[QUINTIPLET_SIZE];
} gtpv1_umts_keys_and_quintuplets_t;

/*
 *  @brief : structure for gsm keys and umts quintuplets IE
 */
typedef struct gtpv1_gsm_keys_and_umts_quintuplets_t {
	uint8_t spare :5; //set as 11111
	uint8_t cksn :3;
	uint8_t no_of_vectors :3;
	uint8_t used_cipher :3;
	uint64_t kc;
	uint16_t quintuplet_length;
	gtpv1_auth_quintuplet_value_t quintuplet[QUINTIPLET_SIZE];
} gtpv1_gsm_keys_and_umts_quintuplets_t;

/*
 *  @brief : structure for used cipher value umts keys and quintuplet IE
 */
typedef struct gtpv1_used_cipher_value_umts_keys_and_quintuplets_t {
	uint8_t gupii :1;
	uint8_t ugipai :1;
	uint8_t used_gprs_integrity_protection_algo :3;
	uint8_t ksi :3;
	uint8_t no_of_vectors :3;
	uint8_t used_cipher :3;
	uint8_t ck[CK_LEN];
	uint8_t ik[IK_LEN];
	uint16_t quintuplet_length;
	gtpv1_auth_quintuplet_value_t quintuplet[QUINTIPLET_SIZE];
} gtpv1_used_cipher_value_umts_keys_and_quintuplets_t;

/*
 *  @brief : structure for ms network capability IE
 */
typedef struct gtpv1_ms_network_capability_value_t {
	uint8_t GEA_1 :1;
	uint8_t sm_capabilities_via_dedicated_channels :1;
	uint8_t sm_capabilities_via_gprs_channels :1;
	uint8_t ucs2_support :1;
	uint8_t ss_screening_indicator :2;
	uint8_t solsa_capability :1;
	uint8_t revision_level_indicator :1;
	uint8_t pfc_feature_mode :1;	
	uint8_t GEA_2 :1;
	uint8_t GEA_3 :1;
	uint8_t GEA_4 :1;
	uint8_t GEA_5 :1;
	uint8_t GEA_6 :1;
	uint8_t GEA_7 :1;
	uint8_t lcs_va_capability :1;
	uint8_t ps_ge_ut_iu_mode_capability :1;
	uint8_t ps_ge_ut_s1_mode_capability :1;
	uint8_t emm_combined_procedure_capability :1;
	uint8_t isr_support :1;
	uint8_t srvcc_to_ge_ut_capability :1;
	uint8_t epc_capability :1;
	uint8_t nf_capability :1;
	uint8_t ge_network_sharing_capability :1;
	uint8_t user_plane_integrity_protection_support :1;
	uint8_t GIA_4 :1;
	uint8_t GIA_5 :1;
	uint8_t GIA_6 :1;
	uint8_t GIA_7 :1;
	uint8_t ePCO_ie_indicator :1;
	uint8_t restriction_on_use_of_enhanced_coverage_capability :1;
	uint8_t dual_connectivity_of_e_ut_with_nr_capability :1;
} gtpv1_ms_network_capability_value_t;

/*
 *  @brief : structure for drx parameter IE
 */
typedef struct gtpv1_drx_parameter_t {
	uint8_t split_pg_cycle_code;
	uint8_t cycle_length :4;
	uint8_t ccch :1;
	uint8_t timer :3;
} gtpv1_drx_parameter_t;

/*
typedef struct gtpv1_mobile_identity_ie_t {
	uint8_t iei;
	uint8_t length;
	union identity_digit {
		struct tmgi_and_optional_mbms_identity {
			uint8_t spare :2;
			uint8_t mbms_sess_indic :1;
			uint8_t mcc_mnc_indic :1;
		} tmgi_and_optional_mbms_identity;
		uint8_t identity_digit_1 :4;
	} identity_digit;
	uint8_t odd_even_indic :1;
	uint8_t type_of_identity :3;
	union identity {
		struct identity_digit_p {
			uint8_t identity_digit_p_1 :4;
			uint8_t identity_digit_p :4;
		} identity_digit_p;
		struct mbms_mnc_mcc_identity {
			uint32_t mbms_service_id :24;
			uint8_t mcc_digit_2 :4;
			uint8_t mcc_digit_1 :4;
			uint8_t mnc_digit_3 :4;
			uint8_t mcc_digit_3 :4;
			uint8_t mnc_digit_2 :4;
			uint8_t mnc_digit_1 :4;
			uint8_t mbms_session_identity;
		} mbms_mnc_mcc_identity;
	} identity;
} gtpv1_mobile_identity_ie_t;
*/

/*
 *  @brief : structure for mm context IE
 */
typedef struct gtpv1_mm_context_ie_t {
	gtpv1_ie_header_t header; /* type = 129 */
	uint8_t security_mode :2;
	union mm_context {
		gtpv1_gsm_key_and_triplet_t gsm_keys_and_triplet;
		gtpv1_umts_keys_and_quintuplets_t umts_keys_and_quintuplets;
		gtpv1_gsm_keys_and_umts_quintuplets_t gsm_keys_and_umts_quintuplets; 
		gtpv1_used_cipher_value_umts_keys_and_quintuplets_t used_cipher_value_umts_keys_and_quintuplets;
	} mm_context;	
	gtpv1_drx_parameter_t drx_parameter;
	uint8_t ms_network_capability_length;
	gtpv1_ms_network_capability_value_t ms_network_capability;
	uint16_t container_length;
//	gtpv1_mobile_identity_ie_t container;
} gtpv1_mm_context_ie_t ;

/*
 *  @brief : structure for gsn address
 */
typedef struct gtpv1_gsn_addr_t {
	uint32_t ipv4;
	uint8_t ipv6[IPV6_ADDR_LEN];
} gtpv1_gsn_addr_t;

/*
 *  @brief : structure for qos
 */
typedef struct gtpv1_qos_t {
	uint8_t allocation_retention_priority;
	uint8_t spare1 :2;
	uint8_t delay_class :3;
	uint8_t reliablity_class :3;
	uint8_t peak_throughput :4;
	uint8_t spare2 :1;
	uint8_t precedence_class :3;
	uint8_t spare3 :3;
	uint8_t mean_throughput :5;
	uint8_t traffic_class :3;
	uint8_t delivery_order :2;
	uint8_t delivery_erroneous_sdu :3;
	uint8_t max_sdu_size;
	uint8_t max_bitrate_uplink;
	uint8_t max_bitrate_downlink;
	uint8_t residual_ber :4;
	uint8_t sdu_error_ratio :4;
	uint8_t transfer_delay :6;
	uint8_t traffic_handling_priority :2;
	uint8_t guaranteed_bitrate_uplink;
	uint8_t guaranteed_bitrate_downlink;
	uint8_t spare4 :3;
	uint8_t signalling_indication :1;
	uint8_t source_statistics_descriptor :4;
	uint8_t max_bitrate_downlink_ext1;
	uint8_t guaranteed_bitrate_downlink_ext1;
	uint8_t max_bitrate_uplink_ext1;
	uint8_t guaranteed_bitrate_uplink_ext1;
	uint8_t max_bitrate_downlink_ext2;
	uint8_t guaranteed_bitrate_downlink_ext2;
	uint8_t max_bitrate_uplink_ext2;
	uint8_t guaranteed_bitrate_uplink_ext2;
} gtpv1_qos_t;

/*
 *  @brief : structure for PDP context IE
 */
typedef struct gtpv1_pdp_context_ie_t {
	gtpv1_ie_header_t header; /* type = 130 */
	uint8_t ea :1;
	uint8_t vaa :1;
	uint8_t asi :1;
	uint8_t order :1;
	uint8_t nsapi :4;
	uint8_t spare :4;
	uint8_t sapi :4;
	uint8_t qos_sub_length;
	gtpv1_qos_t qos_sub;
	uint8_t qos_req_length;
	gtpv1_qos_t qos_req;
	uint8_t qos_neg_length;
	gtpv1_qos_t qos_neg;
	uint16_t sequence_number_down;
	uint16_t sequence_number_up;
	uint8_t send_npdu_number;
	uint8_t rcv_npdu_number;
	uint32_t uplink_teid_cp;
	uint32_t uplink_teid_data1;
	uint8_t pdp_ctxt_identifier;
	uint8_t spare2 :4; //15
	uint8_t pdp_type_org :4;
	uint8_t pdp_type_number1;
	uint8_t pdp_address_length1;
	gtpv1_pdp_addr_t pdp_address1;
	uint8_t ggsn_addr_cp_length;
	gtpv1_gsn_addr_t ggsn_addr_cp;
	uint8_t ggsn_addr_ut_length;
	gtpv1_gsn_addr_t ggsn_addr_ut;
	uint8_t apn_length;
	uint8_t apn[APN_LEN];
	uint8_t spare3 :4;
	uint8_t transaction_identifier1 :4;
	uint8_t transaction_identifier2;
	uint8_t pdp_type_number2;
	uint8_t pdp_address_length2;
	gtpv1_pdp_addr_t pdp_address2;
} gtpv1_pdp_context_ie_t ;

/*
 *  @brief : structure for Access Point Name IE
 */
typedef struct gtpv1_apn_ie_t {
	gtpv1_ie_header_t header; /* type = 131 */
	uint8_t apn_value[APN_LEN];
} gtpv1_apn_ie_t;

/*
 *  @brief : structure for protocol content
 */
typedef struct gtpv1_prot_content_t {
	uint16_t prot_or_cont_id;
	uint8_t length;
	uint8_t content[CONTENT_LEN];
} gtpv1_prot_content_t;

/*
 *  @brief : structure for protocol config options
 */
typedef struct gtpv1_prot_cfg_opts_t {
	uint8_t pco_flag_ext :1;
	uint8_t pco_flag_spare :4;
	uint8_t pco_cfg_proto :3;
	uint8_t pco_content_count;
	gtpv1_prot_content_t pco_content[PCO_LEN];
} gtpv1_prot_cfg_opts_t;

/*
 *  @brief : structure for protocol config option IE
 */
typedef struct gtpv1_protocol_config_options_ie_t { 
	gtpv1_ie_header_t header; /* type = 132 */
	gtpv1_prot_cfg_opts_t pco;
} gtpv1_protocol_config_options_ie_t;

/*
 *  @brief : structure for gsn address IE
 */
typedef struct gtpv1_gsn_addr_ie_t {
	gtpv1_ie_header_t header; /* type = 133 */
	gtpv1_gsn_addr_t gsn_address;
} gtpv1_gsn_addr_ie_t;

/*
 *  @brief : structure for msisdn IE
 */
typedef struct gtpv1_msisdn_ie_t {
	gtpv1_ie_header_t header; /* type = 134 */
	uint8_t msisdn_number_digits[MSISDN_LEN];
} gtpv1_msisdn_ie_t;

/*
 *  @brief : structure for qos IE
 */
typedef struct gtpv1_qos_ie_t{
	gtpv1_ie_header_t header; /* type = 135 */
	gtpv1_qos_t qos;
} gtpv1_qos_ie_t;

/*
 *  @brief : structure for packet filter list delete
 */
typedef struct gtpv1_packet_filter_list_del_t {
	uint8_t spare :4;
	uint8_t filter_id :4;
} gtpv1_packet_filter_list_del_t;

/*
 *  @brief : structure for packet filter list new
 */
typedef struct gtpv1_packet_filter_list_new_t {
	uint8_t spare :2;
	uint8_t filter_direction :2;
	uint8_t filter_id :4;
	uint8_t filter_eval_precedence;
	uint8_t filter_content_length;
	uint8_t filter_content[TFT_BUFF_SIZE];
} gtpv1_packet_filter_list_new_t;

/*
 *  @brief : structure for paramters list
 */
typedef struct gtpv1_parameters_list_t {
	uint8_t parameter_id;
	uint8_t parameter_content_length;
	uint8_t parameter_content[TFT_BUFF_SIZE];
} gtpv1_parameters_list_t;

/*
 *  @brief : structure for traffic flow template IE
 */
typedef struct gtpv1_traffic_flow_tmpl_ie_t {
	gtpv1_ie_header_t header; /* type = 137 */
	uint8_t tft_op_code :3;
	uint8_t e_bit :1;
	uint8_t no_packet_filters :4;
	gtpv1_packet_filter_list_del_t packet_filter_list_del[TFT_BUFF_SIZE];
	gtpv1_packet_filter_list_new_t packet_filter_list_new[TFT_BUFF_SIZE];
	gtpv1_parameters_list_t parameters_list[TFT_BUFF_SIZE];
} gtpv1_traffic_flow_tmpl_ie_t;

/*
 *  @brief : structure for target identification IE
 */
typedef struct gtpv1_target_identification_ie_t {
	gtpv1_ie_header_t header; /* type = 138 */
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
	uint8_t mnc_digit_1 :4;
	uint16_t lac;
	uint8_t rac;
	uint16_t rnc_id;
	uint16_t extended_rnc_id;
} gtpv1_target_identification_ie_t;

/*
 *  @brief : structure for utran transparent container IE
 */
typedef struct gtpv1_utran_transparent_container_ie_t{
	gtpv1_ie_header_t header; /* type = 139 */
	uint8_t utran_transparent_field[RAN_LEN];
} gtpv1_utran_transparent_container_ie_t;

/*
 *  @brief : structure for rab setup information, additional rab setup information IE
 */
typedef struct gtpv1_rab_setup_info_ie_t {
	gtpv1_ie_header_t header; /* type = 140,146 */
	uint8_t spare:4;
	uint8_t nsapi:4;
	uint32_t teid;
	gtpv1_gsn_addr_t rnc_ip_addr;
} gtpv1_rab_setup_info_ie_t;

/*
 *  @brief : structure for extension header type list IE
 */
typedef struct gtpv1_extension_header_type_list_ie_t {
	uint8_t type; /* type = 141 */
	uint8_t length;
	uint8_t extension_type_list[MAX_EXT_TYPE_LIST];
} gtpv1_extension_header_type_list_ie_t;

/*
 *  @brief : structure for trigger ID IE
 */
typedef struct gtpv1_trigger_id_ie_t {
	gtpv1_ie_header_t header; /* type = 142 */
	uint8_t trigger_id[TRIGGER_ID_LEN];
} gtpv1_trigger_id_ie_t;

/*
 *  @brief : structure for omc identity IE
 */
typedef struct gtpv1_omc_identity_ie_t {
	gtpv1_ie_header_t header; /* type = 143 */
	uint8_t omc_identity[OMC_IDENTITY_LEN];
} gtpv1_omc_identity_ie_t;

/*
 *  @brief : structure for ran transparent container IE
 */
typedef struct gtpv1_ran_transparent_container_ie_t{
	gtpv1_ie_header_t header; /* type = 144 */
	uint8_t rtc_field[RAN_LEN];
} gtpv1_ran_transparent_container_ie_t;

/*
 *  @brief : structure for PDP context prioritization IE
 */
typedef struct gtpv1_pdp_context_prioritization_ie_t {
	gtpv1_ie_header_t header; /* type = 145 */
} gtpv1_pdp_context_prioritization_ie_t;

/*
 *  @brief : structure for sgsn number IE
 */
typedef struct gtpv1_sgsn_number_ie_t {
	gtpv1_ie_header_t header; /* type = 147 */
	uint8_t sgsn_number[SGSN_NUMBER_LENGTH];
} gtpv1_sgsn_number_ie_t;

/*
 *  @brief : structure for common flag IE
 */
typedef struct gtpv1_common_flag_ie_t {
	gtpv1_ie_header_t header; /* type = 148 */
	uint8_t dual_addr_bearer_flag :1;
	uint8_t upgrade_qos_supported :1;
	uint8_t nrsn :1;
	uint8_t no_qos_negotiation :1;
	uint8_t mbms_counting_information :1;
	uint8_t ran_procedures_ready :1;
	uint8_t mbms_service_type :1;
	uint8_t prohibit_payload_compression :1;
} gtpv1_common_flag_ie_t;

/*
 *  @brief : structure for apn restriction IE
 */
typedef struct  gtpv1_apn_restriction_ie_t {
	gtpv1_ie_header_t header; /* type = 149 */
	uint8_t restriction_type_value;
} gtpv1_apn_restriction_ie_t;

/*
 *  @brief : structure for radio priority lcs IE
 */
typedef struct gtpv1_radio_priority_lcs_ie_t {
	gtpv1_ie_header_t header; /* type = 150 */
	uint8_t spare :5;
	uint8_t radio_priority_lcs :3;
} gtpv1_radio_priority_lcs_ie_t;

/*
 *  @brief : structure for rat type IE
 */
typedef struct gtpv1_rat_type_ie_t {
	gtpv1_ie_header_t header; /* type = 151 */
	uint8_t rat_type;
} gtpv1_rat_type_ie_t;

/*
 *  @brief : structure for user location information IE
 */
typedef struct gtpv1_user_location_information_ie_t {
	gtpv1_ie_header_t header; /* type = 152 */
	uint8_t geographic_location_type;
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
	uint8_t mnc_digit_1 :4;
	uint16_t lac;
	uint16_t ci_sac_rac;
} gtpv1_user_location_information_ie_t;

/*
 *  @brief : structure for ms time zone IE
 */
typedef struct gtpv1_ms_time_zone_ie_t {
	gtpv1_ie_header_t header; /* type = 153 */
	uint8_t time_zone;
	uint8_t spare :6;
	uint8_t daylight_saving_time :2;
} gtpv1_ms_time_zone_ie_t;

/*
 *  @brief : structure for IMEI IE
 */
typedef struct gtpv1_imei_ie_t {
	gtpv1_ie_header_t header; /* type = 154 */
	uint64_t imei_sv;
} gtpv1_imei_ie_t;

/*
 *  @brief : structure for camel charging information container IE
 */
typedef struct gtpv1_camel_charging_information_container_ie_t {
	gtpv1_ie_header_t header; /* type = 155 */
	uint8_t camel_information_pdp_ie[CAMEL_INFO_PDP_IE_LEN];
} gtpv1_camel_charging_information_container_ie_t;

/*
 *  @brief : structure for MBMS UE context IE
 */
typedef struct gtpv1_mbms_ue_context_ie_t {
	gtpv1_ie_header_t header; /* type = 156 */
	uint8_t linked_nsapi :4;
	uint8_t spare1 :4;
	uint32_t uplink_teid_cp;
	uint8_t enhanced_nsapi;
	uint8_t spare2 :4;
	uint8_t pdp_type_org :4;
	uint8_t pdp_type_number;
	uint8_t pdp_address_length;
	gtpv1_pdp_addr_t pdp_address;
	uint8_t ggsn_addr_cp_length;
	gtpv1_gsn_addr_t ggsn_addr_cp;
	uint8_t apn_length;
	uint8_t apn[APN_LEN];
	uint8_t spare3 :4;
	uint8_t transaction_identifier1 :4;
	uint8_t transaction_identifier2;
} gtpv1_mbms_ue_context_ie_t;

/*
 *  @brief : structure for rim routing address IE
 */
typedef struct gtpv1_rim_routing_addr_ie_t{
	gtpv1_ie_header_t header; /* type = 158 */
	uint8_t rim_routing_addr[RIM_LEN];
} gtpv1_rim_routing_addr_ie_t;

/*
 *  @brief : structure for mbms protocol config option IE
 */
typedef struct gtpv1_mbms_protocol_config_options_ie_t {
	gtpv1_ie_header_t header; /* type = 159 */
	uint8_t mbms_protocol_configuration[PROTOCOL_CONFIG_LENGTH];
} gtpv1_mbms_protocol_config_options_ie_t;

/*
 *  @brief : structure for source rnc PDCP context information IE
 */
typedef struct gtpv1_src_rnc_pdcp_ctxt_info_ie_t {
	gtpv1_ie_header_t header; /* type = 161 */
	uint8_t rrc_container[RRC_LEN];
} gtpv1_src_rnc_pdcp_ctxt_info_ie_t;

/*
 *  @brief : structure for additional trace information IE
 */
typedef struct gtpv1_additional_trace_information_ie_t {
	gtpv1_ie_header_t header; /* type = 162 */
	uint32_t trace_reference_2 :24;
	uint16_t trace_recording_session_reference;
	uint8_t spare1 :6;
	uint8_t triggering_events_in_ggsn_mbms_ctxt :1;
	uint8_t triggering_events_in_ggsn_pdp_ctxt :1;
	uint8_t trace_depth;
	uint8_t spare2 :5;
	uint8_t list_of_interfaces_in_ggsn_gmb :1;
	uint8_t list_of_interfaces_in_ggsn_gi :1;
	uint8_t list_of_interfaces_in_ggsn_gn :1;
	uint8_t trace_activity_control;
} gtpv1_additional_trace_information_ie_t;

/*
 *  @brief : structure for hop counter IE
 */
typedef struct gtpv1_hop_counter_ie_t {
	gtpv1_ie_header_t header; /* type = 163 */
	uint8_t hop_counter;
} gtpv1_hop_counter_ie_t;

/*
 *  @brief : structure for selected plmn ID IE
 */
typedef struct gtpv1_selected_plmn_id_ie_t{
	gtpv1_ie_header_t header; /* type = 164 */
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_1 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
} gtpv1_selected_plmn_id_ie_t;

/*
 *  @brief : structure for bss container IE
 */
typedef struct gtpv1_bss_container_ie_t{
	gtpv1_ie_header_t header; /* type = 173 */
	uint8_t bss_container[BSS_LEN];
} gtpv1_bss_container_ie_t;

/*
 *  @brief : structure for target cell id
 */
typedef struct gtpv1_target_cell_ID_t {
	gtpv1_routing_area_identity_value_t rai_value;
	uint16_t cell_identity;
} gtpv1_target_cell_ID_t;

/*
 *  @brief : structure for cell identification IE
 */
typedef struct gtpv1_cell_identification_ie_t {
	gtpv1_ie_header_t header; /* type = 174 */
	gtpv1_target_cell_ID_t target_cell_id;
	uint8_t source_type;
	union ID {
		gtpv1_target_cell_ID_t source_cell_id;
		struct rnc_id {
			gtpv1_routing_area_identity_value_t rai_value;
			uint8_t spare :4;
			uint8_t rnc_id_value_1 :4;
			uint8_t rnc_id_value_2;
		} rnc_id;
	} ID;
} gtpv1_cell_identification_ie_t;

/*
 *  @brief : structure for PDU numbers IE
 */
typedef struct gtpv1_pdu_numbers_ie_t {
	gtpv1_ie_header_t header; /* type = 175 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint16_t dl_gtpu_seqn_nbr;
	uint16_t ul_gtpu_seqn_nbr;
	uint16_t snd_npdu_nbr;
	uint16_t rcv_npdu_nbr;
} gtpv1_pdu_numbers_ie_t;

/*
 *  @brief : structure for bssgp cause IE
 */
typedef struct gtpv1_bssgp_cause_ie_t {
	gtpv1_ie_header_t header; /* type = 176 */
	uint8_t bssgp_cause;
} gtpv1_bssgp_cause_ie_t;

/*
 *  @brief : structure for rim routing address disc IE
 */
typedef struct gtpv1_rim_routing_addr_disc_ie_t{
	gtpv1_ie_header_t header; /* type = 178 */
	uint8_t spare:4;
	uint8_t discriminator:4;
} gtpv1_rim_routing_addr_disc_ie_t;

/*
 *  @brief : structure for Packet Flow Identifier
 */
typedef struct gtpv1_pfi_t {
	uint8_t spare :1;
	uint8_t pfi_value :7;
} gtpv1_pfi_t;
/*
 *  @brief : structure for list of setup pfcs
 */
typedef struct gtpv1_pfc_list_t {
	uint8_t no_of_pfcs;
	gtpv1_pfi_t pfi_list[PFCS_LEN];
} gtpv1_pfc_list_t;

/*
 *  @brief : structure for list of setup pfcs IE
 */
typedef struct gtpv1_list_of_setup_pfcs_ie_t {
	gtpv1_ie_header_t header; /* type = 179 */
	gtpv1_pfc_list_t list;
} gtpv1_list_of_setup_pfcs_ie_t;

/*
 *  @brief : structure for ps handover xid parameters IE
 */
typedef struct gtpv1_ps_handover_xid_param_ie_t {
	gtpv1_ie_header_t header; /* type = 180 */
	uint8_t spare:4;
	uint8_t sapi:4;
	uint8_t xid_param_length;
	uint8_t xid_param[XID_LEN];
} gtpv1_ps_handover_xid_param_ie_t;

/*
 *  @brief : structure for ms information change reporting action IE
 */
typedef struct gtpv1_ms_info_change_reporting_action_ie_t {
	gtpv1_ie_header_t header; /* type = 181 */
	uint8_t action;
} gtpv1_ms_info_change_reporting_action_ie_t;

/*
 *  @brief : structure for direct tunnel flag IE
 */
typedef struct gtpv1_direct_tunnel_flag_ie_t {
	gtpv1_ie_header_t header; /* type = 182 */
	uint8_t spare :5;
	uint8_t ei :1;
	uint8_t gcsi :1;
	uint8_t dti :1;
} gtpv1_direct_tunnel_flag_ie_t;

/*
 *  @brief : structure for correlation ID IE
 */
typedef struct gtpv1_correlation_id_ie_t {
	gtpv1_ie_header_t header; /* type = 183 */
	uint8_t correlation_id;
} gtpv1_correlation_id_ie_t;

/*
 *  @brief : structure for bearer control mode IE
 */
typedef struct gtpv1_bearer_control_mode_ie_t {
	gtpv1_ie_header_t header; /* type = 184 */
	uint8_t bearer_control_mode;
} gtpv1_bearer_control_mode_ie_t;

/*
 *  @brief : structure for reliable inter rat handover infomation IE
 */
typedef struct gtpv1_reliable_inter_rat_handover_info_ie_t {
	gtpv1_ie_header_t header; /* type = 188 */
	uint8_t handover_info;
} gtpv1_reliable_inter_rat_handover_info_ie_t;

/*
 *  @brief : structure for rfsp index IE
 */
typedef struct gtpv1_rfsp_index_ie_t {
	gtpv1_ie_header_t header; /* type = 189 */
	uint16_t rfsp_index;
} gtpv1_rfsp_index_ie_t;

/*
 *  @brief : structure for FQDN IE
 */
typedef struct gtpv1_fqdn_ie_t {
	gtpv1_ie_header_t header; /* type = 190 */
	uint8_t fqdn[FQDN_LENGTH];
} gtpv1_fqdn_ie_t;

/*
 *  @brief : structure for evolved allocation retention priority 1 IE
 */
typedef struct gtpv1_evolved_allocation_retention_priority_1_ie_t {
	gtpv1_ie_header_t header; /* type = 191 */
	uint8_t spare :1;
	uint8_t pci :1;
	uint8_t pl :4;
	uint8_t spare2 :1;
	uint8_t pvi :1;
} gtpv1_evolved_allocation_retention_priority_1_ie_t;

/*
 *  @brief : structure for evolved allocation retention priority II IE
 */
typedef struct gtpv1_evolved_allocation_retention_priority_II_ie_t {
	gtpv1_ie_header_t header; /* type = 192 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint8_t spare2 :1;
	uint8_t pci :1;
	uint8_t pl :4;
	uint8_t spare3:1;
	uint8_t pvi:1;
} gtpv1_evolved_allocation_retention_priority_II_ie_t;

/*
 *  @brief : structure for extended common flag IE
 */
typedef struct gtpv1_extended_common_flag_ie_t {
	gtpv1_ie_header_t header; /* type = 193 */
	uint8_t uasi :1;
	uint8_t bdwi :1;
	uint8_t pcri :1;
	uint8_t vb :1;
	uint8_t retloc :1;
	uint8_t cpsr :1;
	uint8_t ccrsi :1;
	uint8_t unauthenticated_imsi :1;
} gtpv1_extended_common_flag_ie_t ;

/*
 *  @brief : structure for user csg information IE
 */
typedef struct gtpv1_user_csg_information_ie_t {
	gtpv1_ie_header_t header; /* type = 194 */
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
	uint8_t mnc_digit_1 :4;
	uint8_t spare : 5;
	uint8_t csg_id :3;
	uint32_t csg_id_II :24;
	uint8_t access_mode :2;
	uint8_t spare2 :5;
	uint8_t cmi :1;
} gtpv1_user_csg_information_ie_t;

/*
 *  @brief : structure for csg information reporting action IE
 */
typedef struct gtpv1_csg_information_reporting_action_ie_t {
	gtpv1_ie_header_t header; /* type = 195 */
	uint8_t spare :5;
	uint8_t ucuhc :1;
	uint8_t ucshc :1;
	uint8_t uccsg :1;
} gtpv1_csg_information_reporting_action_ie_t;

/*
 *  @brief : structure for csg ID IE
 */
typedef struct gtpv1_csg_id_ie_t {
	gtpv1_ie_header_t header; /* type = 196 */
	uint8_t spare:5;
	uint8_t csg_id:3;
	uint32_t csg_id2:24;
} gtpv1_csg_id_ie_t;

/*
 *  @brief : structure for csg membership indication IE
 */
typedef struct gtpv1_csg_membership_indication_ie_t {
	gtpv1_ie_header_t header; /* type = 197 */
	uint8_t spare:7;
	uint8_t cmi:1;
} gtpv1_csg_membership_indication_ie_t;

/*
 *  @brief : structure for APN AMBR IE
 */
typedef struct gtpv1_apn_ambr_ie_t {
	gtpv1_ie_header_t header; /* type = 198 */
	uint32_t apn_ambr_uplink;
	uint32_t apn_ambr_downlink;
} gtpv1_apn_ambr_ie_t;

/*
 *  @brief : structure for UE network capability IE
 */
typedef struct gtpv1_ue_network_capability_ie_t {
	gtpv1_ie_header_t header; /* type = 199 */
	uint8_t eea0 :1;
	uint8_t eea1_128 :1;
	uint8_t eea2_128 :1;
	uint8_t eea3_128 :1;
	uint8_t eea4 :1;
	uint8_t eea5 :1;
	uint8_t eea6 :1;
	uint8_t eea7 :1;
	uint8_t eia0 :1;
	uint8_t eia1_128 :1;
	uint8_t eia2_128 :1;
	uint8_t eia3_128 :1;
	uint8_t eia4 :1;
	uint8_t eia5 :1;
	uint8_t eia6 :1;
	uint8_t eia7 :1;
	uint8_t uea0 :1;
	uint8_t uea1 :1;
	uint8_t uea2 :1;
	uint8_t uea3 :1;
	uint8_t uea4 :1;
	uint8_t uea5 :1;
	uint8_t uea6 :1;
	uint8_t uea7 :1;
	uint8_t ucs2 :1;
	uint8_t uia1 :1;
	uint8_t uia2 :1;
	uint8_t uia3 :1;
	uint8_t uia4 :1;
	uint8_t uia5 :1;
	uint8_t uia6 :1;
	uint8_t uia7 :1;
	uint8_t prose_dd :1;
	uint8_t prose :1;
	uint8_t h245_ash :1;
	uint8_t acc_csfb :1;
	uint8_t lpp :1;
	uint8_t lcs :1;
	uint8_t srvcc1x :1;
	uint8_t nf :1;
	uint8_t epco :1;
	uint8_t hc_cp_ciot :1;
	uint8_t erw_opdn :1;
	uint8_t s1_udata :1;
	uint8_t up_ciot :1;
	uint8_t cp_ciot :1;
	uint8_t prose_relay :1;
	uint8_t prose_dc :1;
	uint8_t bearers_15 :1;
	uint8_t sgc :1;
	uint8_t n1mode :1;
	uint8_t dcnr :1;
	uint8_t cp_backoff :1;
	uint8_t restrict_ec :1;
	uint8_t v2x_pc5 :1;
	uint8_t multiple_drb :1;
	uint8_t spare1 :3;
	uint8_t v2xnr_pcf :1;
	uint8_t up_mt_edt :1;
	uint8_t cp_mt_edt :1;
	uint8_t wusa :1;
	uint8_t racs :1;
	uint8_t spare2 :8;
	uint8_t spare3 :8;
	uint8_t spare4 :8;
	uint8_t spare5 :8;
	uint8_t spare6 :8;
} gtpv1_ue_network_capability_ie_t;

/*
 *  @brief : structure for UE AMBR IE
 */
typedef struct gtpv1_ue_ambr_ie_t {
	gtpv1_ie_header_t header; /* type = 200 */
	uint32_t subscribed_ue_ambr_for_uplink;
	uint32_t subscribed_ue_ambr_for_downlink;
	uint32_t authorized_ue_ambr_for_uplink;
	uint32_t authorized_ue_ambr_for_downlink;
} gtpv1_ue_ambr_ie_t;

/*
 *  @brief : structure for APN AMBR with nsapi IE
 */
typedef struct gtpv1_apn_ambr_with_nsapi_ie_t {
	gtpv1_ie_header_t header; /* type = 201 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint32_t authorized_apn_ambr_for_uplink;
	uint32_t authorized_apn_ambr_for_downlink;
} gtpv1_apn_ambr_with_nsapi_ie_t;

/*
 *  @brief : structure for ggsn back off time IE
 */
typedef struct gtpv1_ggsn_back_off_time_ie_t {
	gtpv1_ie_header_t header; /* type = 202 */
	uint8_t timer_unit :3;
	uint8_t timer_value :5;
} gtpv1_ggsn_back_off_time_ie_t;

/*
 *  @brief : structure for signalling priority indication IE
 */
typedef struct gtpv1_signalling_priority_indication_ie_t {
	gtpv1_ie_header_t header; /* type = 203 */
	uint8_t spare :7;
	uint8_t lapi :1;
} gtpv1_signalling_priority_indication_ie_t;

/*
 *  @brief : structure for signalling priority indication with nsapi IE
 */
typedef struct gtpv1_signalling_priority_indication_with_nsapi_ie_t {
	gtpv1_ie_header_t header; /* type = 204 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint8_t spare2 :7;
	uint8_t lapi :1;
} gtpv1_signalling_priority_indication_with_nsapi_ie_t;

/*
 *  @brief : structure for higher bitrates than 16 mbps flag IE
 */
typedef struct gtpv1_higher_bitrates_than_16_mbps_flag_ie_t {
	gtpv1_ie_header_t header; /* type = 205 */
	uint8_t higher_bitrates_than_16_mbps_flag;
} gtpv1_higher_bitrates_than_16_mbps_flag_ie_t;

/*
 *  @brief : structure for MS classmark 2
 */
typedef struct gtpv1_ms_classmark_2_t {
	uint8_t ms_classmark_2_len;
	uint8_t spare1 :1;
	uint8_t rev_level :2;
	uint8_t es_ind :1;
	uint8_t a5_1 :1;
	uint8_t rf_power_cap :3;
	uint8_t spare2 :1;
	uint8_t ps_cap :1;
	uint8_t ss_screen_ind :2;
	uint8_t sm_cap :1;
	uint8_t vbs :1;
	uint8_t vgcs :1;
	uint8_t fc :1;
	uint8_t cm3 :1;
	uint8_t spare3 :1;
	uint8_t lcsvacap :1;
	uint8_t ucs2 :1;
	uint8_t solsa :1;
	uint8_t cmsp :1;
	uint8_t a5_3 :1;
	uint8_t a5_2 :1;
} gtpv1_ms_classmark_2_t;

/*
 *  @brief : structure for MS classmark 3 IE
 */
typedef struct gtpv1_ms_classmark_3_t {
	uint8_t ms_classmark_3_len;
	uint8_t spare1 :1;
	uint8_t mult_band_supp :3;
	uint8_t a5_bits :3;
	uint8_t assoc_radio_cap_1 :4;
	uint8_t assoc_radio_cap_2 :4;
	uint8_t spare2 :4;
	uint8_t r_support :1;
	uint8_t r_gsm_assoc_radio_cap :3;
	uint8_t hscsd_mult_slot_cap :1;
	uint8_t hscsd_mult_slot_class :5;
	uint8_t ucs2_treatment :1;
	uint8_t extended_meas_cap :1;
	uint8_t ms_meas_cap :1;
	uint8_t sms_value :4;
	uint8_t sm_value :4;
	uint8_t ms_pos_method_cap :1;
	uint8_t ms_pos_method :5;
	uint8_t ecsd_multislot_cap :1;
	uint8_t ecsd_multislot_class :5;
	uint8_t psk8_struct :1;
	uint8_t mod_cap :1;
	uint8_t rf_pwr_cap_1 :1;
	uint8_t rf_pwr_cap_1_val :2;
	uint8_t rf_pwr_cap_2 :1;
	uint8_t rf_pwr_cap_2_val :2;
	uint8_t gsm_400_bands_supp :1;
	uint8_t gsm_400_bands_val :2;
	uint8_t gsm_400_assoc_radio_cap :4;
	uint8_t gsm_850_assoc_radio_cap :1;
	uint8_t gsm_850_assoc_radio_cap_val :4;
	uint8_t gsm_1900_assoc_radio_cap :1;
	uint8_t gsm_1900_assoc_radio_cap_val :4;
	uint8_t umts_fdd_rat_cap :1;
	uint8_t umts_tdd_rat_cap :1;
	uint8_t cdma2000_rat_cap :1;
	uint8_t	dtm_gprs_multislot_class :1;
	uint8_t	dtm_gprs_multislot_val :2;
	uint8_t single_slot_dtm :1;
	uint8_t dtm_egprs_multislot_class :1;
	uint8_t dtm_egprs_multislot_val :2;
	uint8_t single_band_supp :1;
	uint8_t single_band_supp_val :4;
	uint8_t gsm_750_assoc_radio_cap :1;
	uint8_t gsm_750_assoc_radio_cap_val :4;
	uint8_t umts_1_28_mcps_tdd_rat_cap :1;
	uint8_t geran_feature_package :1; 
	uint8_t ext_dtm_gprs_multislot_class :1;
	uint8_t ext_dtm_gprs_multislot_val :2;
	uint8_t ext_dtm_egprs_multislot_val :2;
	uint8_t high_multislot_cap :1;
	uint8_t high_multislot_val :2;
	uint8_t geran_iu_mode_supp :1;
	uint8_t geran_feature_package_2 :1;
	uint8_t gmsk_multislot_power_prof :2;
	uint8_t psk8_multislot_power_prof :2;
	uint8_t t_gsm_400_bands_supp :1;
	uint8_t t_gsm_400_bands_val :2;
	uint8_t t_gsm_400_assoc_radio_cap :4;
	uint8_t t_gsm_900_assoc_radio_cap :1;
	uint8_t dl_advanced_rx_perf :2;
	uint8_t dtm_enhancements_cap :1;
	uint8_t dtm_gprs_high_multislot_cap :1;
	uint8_t dtm_gprs_high_multislot_val :3;
	uint8_t offset_required :1;
	uint8_t dtm_egprs_high_multislot_cap :1;
	uint8_t dtm_egprs_high_multislot_val :3;
	uint8_t repeated_acch_capability :1;
	uint8_t gsm_710_assoc_radio_cap :1;
	uint8_t gsm_710_assoc_radio_val :4;
	uint8_t t_gsm_810_assoc_radio_cap :1;
	uint8_t t_gsm_810_assoc_radio_val :4;
	uint8_t ciphering_mode_setting_cap :1;
	uint8_t add_pos_cap :1;
	uint8_t e_utra_fdd_supp :1;
	uint8_t e_utra_tdd_supp :1;
	uint8_t e_utra_meas_rep_supp :1;
	uint8_t prio_resel_supp :1;
	uint8_t utra_csg_cells_rep :1;
	uint8_t vamos_level :2;
	uint8_t tighter_capability :2;
	uint8_t sel_ciph_dl_sacch :1;
	uint8_t cs_ps_srvcc_geran_utra :2;
	uint8_t cs_ps_srvcc_geran_eutra :2;
	uint8_t geran_net_sharing :1;
	uint8_t e_utra_wb_rsrq_meas_supp :1;
	uint8_t er_band_support :1;
	uint8_t utra_mult_band_ind_supp :1;
	uint8_t e_utra_mult_band_ind_supp :1;
	uint8_t extended_tsc_set_cap_supp :1;
	uint8_t extended_earfcn_val_range :1;
	uint8_t spare3 :4;
} gtpv1_ms_classmark_3_t;

/*
 *  @brief : structure sup codec list IE
 */
typedef struct gtpv1_sup_codec_list_t {
	uint8_t sysid;
	uint8_t len_bitmap_sysid;
	uint8_t codec_bitmap_1_8;
	uint8_t codec_bitmap_9_16;
} gtpv1_sup_codec_list_t;

/*
 *  @brief : structure for additional mm context for srvcc IE
 */
typedef struct gtpv1_additional_mm_ctxt_for_srvcc_ie_t {
	gtpv1_ie_header_t header; /* type = 207 */
	gtpv1_ms_classmark_2_t ms_classmark_2;
	gtpv1_ms_classmark_3_t ms_classmark_3;
	uint8_t sup_codec_list_len;
	gtpv1_sup_codec_list_t sup_codec_list[MS_LEN];
} gtpv1_additional_mm_ctxt_for_srvcc_ie_t;

/*
 *  @brief : structure for additional flags for srvcc IE
 */
typedef struct gtpv1_additional_flags_for_srvcc_ie_t {
	gtpv1_ie_header_t header; /* type = 208 */
	uint8_t spare:7;
	uint8_t ics:1;
} gtpv1_additional_flags_for_srvcc_ie_t;

/*
 *  @brief : structure for stn sr IE
 */
typedef struct gtpv1_stn_sr_ie_t {
	gtpv1_ie_header_t header; /* type = 209 */
	uint8_t nanpi;
	gtpv1_digits_t digits[STN_SR_LEN];
} gtpv1_stn_sr_ie_t;

/*
 *  @brief : structure for c msisdn IE
 */
typedef struct gtpv1_c_msisdn_ie_t {
	gtpv1_ie_header_t header; /* type = 210 */
	uint8_t msisdn[C_MSISDN_LEN];
} gtpv1_c_msisdn_ie_t;

/*
 *  @brief : structure for extended ranap cause IE
 */
typedef struct gtpv1_extended_ranap_cause_ie_t {
	gtpv1_ie_header_t header; /* type = 211 */
	uint16_t extended_ranap_cause;
} gtpv1_extended_ranap_cause_ie_t;

/*
 *  @brief : structure for enodeb ID IE
 */
typedef struct gtpv1_enodeb_id_ie_t {
	gtpv1_ie_header_t header; /* type = 212 */
	uint8_t enodeb_type;
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
	uint8_t mnc_digit_1 :4;
	uint8_t spare:4;
	uint8_t macro_enodeb_id:4;
	uint16_t macro_enodeb_id2;
	uint8_t home_enodeb_id:4;
	uint32_t home_enodeb_id2:24;
	uint16_t tac;
} gtpv1_enodeb_id_ie_t;

/*
 *  @brief : structure for selection mode with nsapi IE
 */
typedef struct gtpv1_selection_mode_with_nsapi_ie_t {
	gtpv1_ie_header_t header; /* type = 213 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint8_t spare2 :6;
	uint8_t selection_mode_value :2;
} gtpv1_selection_mode_with_nsapi_ie_t;

/*
 *  @brief : structure for uli timestamp IE
 */
typedef struct gtpv1_uli_timestamp_ie_t {
	gtpv1_ie_header_t header; /* type = 214 */
	uint32_t timestamp_value;
} gtpv1_uli_timestamp_ie_t;

/*
 *  @brief : structure for local home network id with nsapi IE
 */
typedef struct gtpv1_local_home_network_id_with_nsapi_ie_t {
	gtpv1_ie_header_t header; /* type = 215 */
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint8_t local_home_network_id_with_nsapi[LHN_ID_LEN];
} gtpv1_local_home_network_id_with_nsapi_ie_t;

/*
 *  @brief : structure for cn opertore selection entity IE
 */
typedef struct gtpv1_cn_operator_selection_entity_ie_t { 
	gtpv1_ie_header_t header; /* type = 216 */
	uint8_t spare :6;
	uint8_t selection_entity :2;
} gtpv1_cn_operator_selection_entity_ie_t;

/*
 *  @brief : structure for UE usage type IE
 */
typedef struct gtpv1_ue_usage_type_ie_t {
	gtpv1_ie_header_t header; /* type = 217 */
	uint32_t ue_usage_type_value;
} gtpv1_ue_usage_type_ie_t;

/*
 *  @brief : structure for extended common flag 2 IE
 */
typedef struct gtpv1_extended_common_flag_2_ie_t {
	gtpv1_ie_header_t header; /* type = 218 */
	uint8_t spare :5;
	uint8_t pmts_mi :1;
	uint8_t dtci :1;
	uint8_t pnsi :1;
} gtpv1_extended_common_flag_2_ie_t;

/*
 *  @brief : structure for node identifier IE
 */
typedef struct gtpv1_node_identifier_ie_t {
	gtpv1_ie_header_t header; /* type = 219 */
	uint8_t len_of_node_name;
	uint8_t node_name[NODE_LEN];
	uint8_t len_of_node_realm;
	uint8_t node_realm[NODE_LEN];
} gtpv1_node_identifier_ie_t;

/*
 *  @brief : structure for UE scef PDN connection IE
 */
typedef struct gtpv1_ue_scef_pdn_connection_ie_t {
	gtpv1_ie_header_t header; /* type = 221 */
	uint8_t apn_length;
	uint8_t apn[APN_LEN];
	uint8_t spare :4;
	uint8_t nsapi :4;
	uint8_t scef_id_length;
	uint8_t scef_id[SCEF_ID_LEN];
} gtpv1_ue_scef_pdn_connection_ie_t;

/*
 *  @brief : structure for IOV updates counter IE
 */
typedef struct gtpv1_iov_updates_counter_ie_t {
	gtpv1_ie_header_t header; /* type = 222 */
	uint8_t iov_updates_counter;
} gtpv1_iov_updates_counter_ie_t;

/*
 *  @brief : structure for mapped UE usage type IE
 */
typedef struct gtpv1_mapped_ue_usage_type_ie_t {
	gtpv1_ie_header_t header; /* type = 223 */
	uint16_t mapped_ue_usage_type;
} gtpv1_mapped_ue_usage_type_ie_t;

/*
 *  @brief : structure for UP function selection indication IE
 */
typedef struct gtpv1_up_function_selection_indication_ie_t {
	gtpv1_ie_header_t header; /* type = 224 */
	uint8_t spare :7; 
	uint8_t dcnr :1;
} gtpv1_up_function_selection_indication_ie_t;

/*
 *  @brief : structure for charging gateway address IE
 */
typedef struct gtpv1_charging_gateway_addr_ie_t {
	gtpv1_ie_header_t header; /* type = 251 */
	uint32_t ipv4_addr;
	uint8_t ipv6_addr[IPV6_ADDR_LEN];
} gtpv1_charging_gateway_addr_ie_t;

/*
 *  @brief : structure for private extension IE
 */
typedef struct gtpv1_private_extension_ie_t {
	gtpv1_ie_header_t header; /* type = 255 */
	uint16_t extension_identifier;
	uint8_t extension_value[PRIVATE_EXTENSION_LEN];
} gtpv1_private_extension_ie_t;

#ifdef __cplusplus
}
#endif

#endif /* __GTPV1_IES_H__ */
