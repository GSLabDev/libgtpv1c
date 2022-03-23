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

#ifndef __GTPV1_MESSAGES_H__
#define __GTPV1_MESSAGES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "gtpv1_ies.h"

/*
 *  @brief : enum for gtpv1 Messages type
 */
enum MESSAGE_TYPE {
	GTPV1_ECHO_REQUEST = 1,
	GTPV1_ECHO_RESPONSE,
	GTPV1_VERSION_NOT_SUPPORTED,
	GTPV1_CREATE_PDP_CTXT_REQ = 16,
	GTPV1_CREATE_PDP_CTXT_RSP,
	GTPV1_UPDATE_PDP_CTXT_REQ,
	GTPV1_UPDATE_PDP_CTXT_RSP,
	GTPV1_DELETE_PDP_CTXT_REQ,
	GTPV1_DELETE_PDP_CTXT_RSP,
	GTPV1_INITIATE_PDP_CTXT_ACTIVATION_REQ,
	GTPV1_INITIATE_PDP_CTXT_ACTIVATION_RSP,
	GTPV1_PDU_NOTIFICATION_REQ = 27,
	GTPV1_PDU_NOTIFICATION_RSP,
	GTPV1_PDU_NOTIFICATION_REJECT_REQ,
	GTPV1_PDU_NOTIFICATION_REJECT_RSP,
	GTPV1_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
	GTPV1_SEND_ROUTEING_INFO_FOR_GPRS_REQ,
	GTPV1_SEND_ROUTEING_INFO_FOR_GPRS_RSP,
	GTPV1_FAILURE_REPORT_REQ,
	GTPV1_FAILURE_REPORT_RSP,
	GTPV1_NOTE_MS_GPRS_PRESENT_REQ,
	GTPV1_NOTE_MS_GPRS_PRESENT_RSP,
	GTPV1_IDENTIFICATION_REQ = 48,
	GTPV1_IDENTIFICATION_RSP,
	GTPV1_SGSN_CONTEXT_REQ,
	GTPV1_SGSN_CONTEXT_RSP,
	GTPV1_SGSN_CONTEXT_ACK,
	GTPV1_FORWARD_RELOCATION_REQUEST,
	GTPV1_FORWARD_RELOCATION_RESPONSE,
	GTPV1_FORWARD_RELOCATION_COMPLETE,
	GTPV1_RELOCATION_CANCEL_REQ,
	GTPV1_RELOCATION_CANCEL_RSP,
	GTPV1_FORWARD_SRNS_CONTEXT,
	GTPV1_FORWARD_RELOCATION_COMPLETE_ACK,
	GTPV1_FORWARD_SRNS_CONTEXT_ACK,
	GTPV1_UE_REGISTRATION_QUERY_REQ,
	GTPV1_UE_REGISTRATION_QUERY_RSP,
	GTPV1_RAN_INFO_RELAY = 70,
	GTPV1_MBMS_NOTIFICATION_REQ = 96,
	GTPV1_MBMS_NOTIFICATION_RSP,
	GTPV1_MS_INFO_CHANGE_NOTIFICATION_REQ = 128,
	GTPV1_MS_INFO_CHANGE_NOTIFICATION_RSP
};

/*
 *  @brief : structure for gtpv1 Echo Request Message
 */
typedef struct gtpv1_echo_req_t {
	gtpv1_header_t header;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_echo_req_t;

/*
 *  @brief : structure for gtpv1 Echo Response Message
 */
typedef struct gtpv1_echo_rsp_t {
	gtpv1_header_t header;
	gtpv1_recovery_ie_t recovery;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_echo_rsp_t;

/*
 *  @brief : structure for gtpv1 version not supported Message
 */
typedef struct gtpv1_version_not_supported_t {
	gtpv1_header_t header;
} gtpv1_version_not_supported_t;

/*
 *  @brief : structure for gtpv1 create PDP context Request Message
 */
typedef struct gtpv1_create_pdp_ctxt_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_selection_mode_ie_t selection_mode;
	gtpv1_teid_ie_t tunn_endpt_idnt_data_1;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these nsapi will come
		-> NSAPI
		-> LINKED NSAPI
		So considered first as nsapi and second as linked nsapi
	*/
	gtpv1_nsapi_ie_t nsapi;
	gtpv1_nsapi_ie_t linked_nsapi;
	gtpv1_chrgng_char_ie_t chrgng_char;
	gtpv1_end_user_address_ie_t end_user_address;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_apn_ie_t apn;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these gsn address will come
		-> SGSN Address for signalling
		-> SGSN Address for user traffic
		So considered first as SGSN Address for signalling and second as SGSN Address for user traffic
	*/
	gtpv1_gsn_addr_ie_t sgsn_address_for_signalling;
	gtpv1_gsn_addr_ie_t sgsn_address_for_user_traffic;
	gtpv1_msisdn_ie_t msisdn;
	gtpv1_qos_ie_t qos_profile;
	gtpv1_traffic_flow_tmpl_ie_t tft;
	gtpv1_imei_ie_t imei_sv;
	gtpv1_common_flag_ie_t common_flag;
	gtpv1_apn_restriction_ie_t apn_restriction;
	gtpv1_evolved_allocation_retention_priority_1_ie_t evolved_allocation_retention_priority_1;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_apn_ambr_ie_t apn_ambr;
	gtpv1_private_extension_ie_t private_extension;
	gtpv1_rat_type_ie_t rat_type;
	gtpv1_recovery_ie_t recovery;
	gtpv1_routing_area_identity_ie_t routing_area_identity;
	gtpv1_trace_reference_ie_t trace_reference;
	gtpv1_trace_type_ie_t trace_type;
	gtpv1_trigger_id_ie_t trigger_id;
	gtpv1_omc_identity_ie_t omc_identity;
	gtpv1_user_location_information_ie_t user_location_information;
	gtpv1_ms_time_zone_ie_t ms_time_zone;
	gtpv1_camel_charging_information_container_ie_t camel_charging_information_container;
	gtpv1_additional_trace_information_ie_t additional_trace_information;
	gtpv1_correlation_id_ie_t correlation_id;
	gtpv1_user_csg_information_ie_t user_csg_information;
	gtpv1_signalling_priority_indication_ie_t signalling_priority_indication;
	gtpv1_cn_operator_selection_entity_ie_t cn_operator_selection_entity;
	gtpv1_mapped_ue_usage_type_ie_t mapped_ue_usage_type;
	gtpv1_up_function_selection_indication_ie_t up_function_selection_indication;
} gtpv1_create_pdp_ctxt_req_t;

/*
 *  @brief : structure for gtpv1 create PDP context Response Message
 */
typedef struct gtpv1_create_pdp_ctxt_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_reordering_req_ie_t reordering_req;
	gtpv1_recovery_ie_t recovery;
	gtpv1_teid_ie_t tunn_endpt_idnt_data_1;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_nsapi_ie_t nsapi;
	gtpv1_charging_id_ie_t charging_id;
	gtpv1_end_user_address_ie_t end_user_address;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these gsn address will come
		-> GGSN Address for Control Plane
		-> GGSN Address for user traffic
		-> Alternative GGSN Address for Control Plane
		-> Alternative GGSN Address for user traffic
		So it will based on the assumption of application in which order they want to send or accept
	*/
	gtpv1_gsn_addr_ie_t gsn_addr_1;
	gtpv1_gsn_addr_ie_t gsn_addr_2;
	gtpv1_gsn_addr_ie_t gsn_addr_3;
	gtpv1_gsn_addr_ie_t gsn_addr_4;
	gtpv1_qos_ie_t qos_profile;
	gtpv1_charging_gateway_addr_ie_t charging_gateway_addr;
	gtpv1_charging_gateway_addr_ie_t alt_charging_gateway_addr;
	gtpv1_common_flag_ie_t common_flag;
	gtpv1_apn_restriction_ie_t apn_restriction;
	gtpv1_ms_info_change_reporting_action_ie_t ms_info_change_reporting_action;
	gtpv1_bearer_control_mode_ie_t bearer_control;
	gtpv1_evolved_allocation_retention_priority_1_ie_t evolved_allocation_retention_priority_1;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_csg_information_reporting_action_ie_t csg_information_reporting_action;
	gtpv1_apn_ambr_ie_t apn_ambr;
	gtpv1_ggsn_back_off_time_ie_t ggsn_back_off_time;
	gtpv1_extended_common_flag_2_ie_t extended_common_flag_2;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_create_pdp_ctxt_rsp_t;

/*
 *  @brief : structure for gtpv1 SGSN initiated update PDP context Request Message
 */
typedef struct gtpv1_update_pdp_ctxt_req_sgsn_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_routing_area_identity_ie_t routing_area_identity;
	gtpv1_recovery_ie_t recovery;
	gtpv1_teid_ie_t tunn_endpt_idnt_data_1;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_nsapi_ie_t nsapi;
	gtpv1_trace_reference_ie_t trace_reference;
	gtpv1_trace_type_ie_t trace_type;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these gsn address will come
		-> SGSN Address for Control Plane
		-> SGSN Address for user traffic
		-> Alternative SGSN Address for Control Plane
		-> Alternative SGSN Address for user traffic
		So it will based on the assumption of application in which order they want to send or accept
	*/
	gtpv1_gsn_addr_ie_t gsn_addr_1;
	gtpv1_gsn_addr_ie_t gsn_addr_2;
	gtpv1_gsn_addr_ie_t gsn_addr_3;
	gtpv1_gsn_addr_ie_t gsn_addr_4;
	gtpv1_qos_ie_t qos_profile;
	gtpv1_traffic_flow_tmpl_ie_t tft;
	gtpv1_trigger_id_ie_t trigger_id;
	gtpv1_omc_identity_ie_t omc_identity;
	gtpv1_common_flag_ie_t common_flag;
	gtpv1_rat_type_ie_t rat_type;
	gtpv1_user_location_information_ie_t user_location_information;
	gtpv1_ms_time_zone_ie_t ms_time_zone;
	gtpv1_additional_trace_information_ie_t additional_trace_information;
	gtpv1_direct_tunnel_flag_ie_t direct_tunnel_flag;
	gtpv1_evolved_allocation_retention_priority_1_ie_t evolved_allocation_retention_priority_1;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_user_csg_information_ie_t user_csg_information;
	gtpv1_apn_ambr_ie_t apn_ambr;
	gtpv1_signalling_priority_indication_ie_t signalling_priority_indication;
	gtpv1_cn_operator_selection_entity_ie_t cn_operator_selection_entity;
	gtpv1_imei_ie_t imei_sv;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_update_pdp_ctxt_req_sgsn_t;

/*
 *  @brief : structure for gtpv1 GGSN initiated update PDP context Request Message
 */
typedef struct gtpv1_update_pdp_ctxt_req_ggsn_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_recovery_ie_t recovery;
	gtpv1_nsapi_ie_t nsapi;
	gtpv1_end_user_address_ie_t end_user_address;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_qos_ie_t qos_profile;
	gtpv1_traffic_flow_tmpl_ie_t tft;
	gtpv1_common_flag_ie_t common_flag;
	gtpv1_apn_restriction_ie_t apn_restriction;
	gtpv1_ms_info_change_reporting_action_ie_t ms_info_change_reporting_action;
	gtpv1_direct_tunnel_flag_ie_t direct_tunnel_flag;
	gtpv1_bearer_control_mode_ie_t bearer_control;
	gtpv1_evolved_allocation_retention_priority_1_ie_t evolved_allocation_retention_priority_1;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_csg_information_reporting_action_ie_t csg_information_reporting_action;
	gtpv1_apn_ambr_ie_t apn_ambr;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_update_pdp_ctxt_req_ggsn_t;

/*
 *  @brief : structure for gtpv1 update PDP context Reponse Message sent by a GGSN
 */
typedef struct gtpv1_update_pdp_ctxt_rsp_ggsn_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_recovery_ie_t recovery;
	gtpv1_teid_ie_t tunn_endpt_idnt_data_1;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_charging_id_ie_t charging_id;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these gsn address will come
		-> GGSN Address for Control Plane
		-> GGSN Address for user traffic
		-> Alternative GGSN Address for Control Plane
		-> Alternative GGSN Address for user traffic
		So it will based on the assumption of application in which order they want to send or accept
	*/
	gtpv1_gsn_addr_ie_t gsn_addr_1;
	gtpv1_gsn_addr_ie_t gsn_addr_2;
	gtpv1_gsn_addr_ie_t gsn_addr_3;
	gtpv1_gsn_addr_ie_t gsn_addr_4;
	gtpv1_qos_ie_t qos_profile;
	gtpv1_charging_gateway_addr_ie_t charging_gateway_addr;
	gtpv1_charging_gateway_addr_ie_t alt_charging_gateway_addr;
	gtpv1_common_flag_ie_t common_flag;
	gtpv1_apn_restriction_ie_t apn_restriction;
	gtpv1_bearer_control_mode_ie_t bearer_control;
	gtpv1_ms_info_change_reporting_action_ie_t ms_info_change_reporting_action;
	gtpv1_evolved_allocation_retention_priority_1_ie_t evolved_allocation_retention_priority_1;
	gtpv1_csg_information_reporting_action_ie_t csg_information_reporting_action;
	gtpv1_apn_ambr_ie_t apn_ambr;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_update_pdp_ctxt_rsp_ggsn_t;

/*
 *  @brief : structure for gtpv1 update PDP context Reponse Message sent by a SGSN
 */
typedef struct gtpv1_update_pdp_ctxt_rsp_sgsn_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_recovery_ie_t recovery;
	gtpv1_teid_ie_t tunn_endpt_idnt_data_1;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_gsn_addr_ie_t sgsn_address_for_user_traffic;
	gtpv1_qos_ie_t qos_profile;
	gtpv1_user_location_information_ie_t user_location_information;
	gtpv1_ms_time_zone_ie_t ms_time_zone;
	gtpv1_direct_tunnel_flag_ie_t direct_tunnel_flag;
	gtpv1_evolved_allocation_retention_priority_1_ie_t evolved_allocation_retention_priority_1;
	gtpv1_apn_ambr_ie_t apn_ambr;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_update_pdp_ctxt_rsp_sgsn_t;

/*
 *  @brief : structure for gtpv1 delete PDP context Request Message
 */
typedef struct gtpv1_delete_pdp_ctxt_req_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_teardown_ind_ie_t teardown_ind;
	gtpv1_nsapi_ie_t nsapi;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_user_location_information_ie_t user_location_information;
	gtpv1_ms_time_zone_ie_t ms_time_zone;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_uli_timestamp_ie_t uli_timestamp;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_delete_pdp_ctxt_req_t;

/*
 *  @brief : structure for gtpv1 delete PDP context Response Message
 */
typedef struct gtpv1_delete_pdp_ctxt_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_user_location_information_ie_t user_location_information; 
	gtpv1_ms_time_zone_ie_t ms_time_zone;
	gtpv1_uli_timestamp_ie_t uli_timestamp;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_delete_pdp_ctxt_rsp_t;

/*
 *  @brief : structure for gtpv1 initiate PDP context Request Message
 */
typedef struct gtpv1_initiate_pdp_ctxt_active_req_t {
	gtpv1_header_t header;
	gtpv1_nsapi_ie_t linked_nsapi;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_qos_ie_t qos_profile;
	gtpv1_traffic_flow_tmpl_ie_t tft;
	gtpv1_correlation_id_ie_t correlation_id;
	gtpv1_evolved_allocation_retention_priority_1_ie_t evolved_allocation_retention_priority_1;
	gtpv1_private_extension_ie_t private_extension;		
} gtpv1_initiate_pdp_ctxt_active_req_t;

/*
 *  @brief : structure for gtpv1 initiate PDP context Response Message
 */
typedef struct gtpv1_initiate_pdp_ctxt_active_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_private_extension_ie_t private_extension;	
} gtpv1_initiate_pdp_ctxt_active_rsp_t;

/*
 *  @brief : structure for gtpv1 PDU notification Request Message
 */
typedef struct gtpv1_pdu_notification_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_end_user_address_ie_t end_user_address;
	gtpv1_apn_ie_t apn;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_gsn_addr_ie_t ggsn_addr_control_plane;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_pdu_notification_req_t;

/*
 *  @brief : structure for gtpv1 PDU notification Response Message
 */
typedef struct gtpv1_pdu_notification_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_pdu_notification_rsp_t;

/*
 *  @brief : structure for gtpv1 PDU notification reject Request Message
 */
typedef struct gtpv1_pdu_notification_reject_req_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_end_user_address_ie_t end_user_address;
	gtpv1_apn_ie_t apn;
	gtpv1_protocol_config_options_ie_t protocol_config_options;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_pdu_notification_reject_req_t;

/*
 *  @brief : structure for gtpv1 PDU notification reject Response Message
 */
typedef struct gtpv1_pdu_notification_reject_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_pdu_notification_reject_rsp_t;

/*
 *  @brief : structure for gtpv1 send routeing information for gprs Request Message
 */
typedef struct gtpv1_send_routeing_info_for_gprs_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_send_routeing_info_for_gprs_req_t;

/*
 *  @brief : structure for gtpv1 send routeing information for gprs Response Message
 */
typedef struct gtpv1_send_routeing_info_for_gprs_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_imsi_ie_t imsi;
	gtpv1_map_cause_ie_t map_cause;
	gtpv1_ms_not_rechable_reason_ie_t ms_not_rechable_reason;
	gtpv1_gsn_addr_ie_t gsn_addr;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_send_routeing_info_for_gprs_rsp_t;

/*
 *  @brief : structure for gtpv1 failure report Request Message
 */
typedef struct gtpv1_failure_report_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_failure_report_req_t;

/*
 *  @brief : structure for gtpv1 failure report Response Message
 */
typedef struct gtpv1_failure_report_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_map_cause_ie_t map_cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_failure_report_rsp_t;

/*
 *  @brief : structure for gtpv1 note ms gprs present Request Message
 */
typedef struct gtpv1_note_ms_gprs_present_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_gsn_addr_ie_t gsn_addr;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_note_ms_gprs_present_req_t;

/*
 *  @brief : structure for gtpv1 note ms gprs present Response Message
 */
typedef struct gtpv1_note_ms_gprs_present_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_note_ms_gprs_present_rsp_t;

/*
 *  @brief : structure for gtpv1 sgsn context Request Message
 */
typedef struct gtpv1_sgsn_ctxt_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_routing_area_identity_ie_t routing_area_identity;
	gtpv1_temporary_logical_link_identifier_ie_t temporary_logical_link_identifier;
	gtpv1_packet_tmsi_ie_t packet_tmsi;
	gtpv1_p_tmsi_signature_ie_t p_tmsi_signature;
	gtpv1_ms_validated_ie_t ms_validated;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_gsn_addr_ie_t sgsn_address_for_control_plane;
	gtpv1_gsn_addr_ie_t alternative_sgsn_address_for_control_plane;
	gtpv1_sgsn_number_ie_t sgsn_number;
	gtpv1_rat_type_ie_t rat_type;
	gtpv1_hop_counter_ie_t hop_counter;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_sgsn_ctxt_req_t;

/*
 *  @brief : structure for gtpv1 sgsn context Response Message
 */
typedef struct gtpv1_sgsn_ctxt_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_imsi_ie_t imsi;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_rab_context_ie_t rab_context;
	gtpv1_radio_priority_sms_ie_t radio_priority_sms;
	gtpv1_radio_priority_ie_t radio_priority;
	gtpv1_packet_flow_id_ie_t packet_flow_id;
	gtpv1_chrgng_char_ie_t chrgng_char;
	gtpv1_radio_priority_lcs_ie_t radio_priority_lcs;
	gtpv1_mm_context_ie_t mm_context;
	gtpv1_pdp_context_ie_t pdp_context;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these gsn address will come
		-> SGSN Address for Control Plane
		-> Alternative GGSN Address for Control Plane
		-> Alternative GGSN Address for user traffic
		So it will based on the assumption of application in which order they want to send or accept
	*/
	gtpv1_gsn_addr_ie_t gsn_addr_1;
	gtpv1_gsn_addr_ie_t gsn_addr_2;
	gtpv1_gsn_addr_ie_t gsn_addr_3;
	gtpv1_pdp_context_prioritization_ie_t pdp_context_prioritization;
	gtpv1_mbms_ue_context_ie_t mbms_ue_context;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these RFSP index will come
		-> subscribed rfsp index
		-> rfsp index in use
		So considered first as subscribed rfsp index and second as rfsp index in use
	*/
	gtpv1_rfsp_index_ie_t subscribed_rfsp_index;
	gtpv1_rfsp_index_ie_t rfsp_index_in_use;
	gtpv1_fqdn_ie_t co_located_ggsn_pgw_fqdn;
	gtpv1_evolved_allocation_retention_priority_II_ie_t evolved_allocation_retention_priority_II;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_ue_network_capability_ie_t ue_network_capability;
	gtpv1_ue_ambr_ie_t ue_ambr;
	gtpv1_apn_ambr_with_nsapi_ie_t apn_ambr_with_nsapi;
	gtpv1_signalling_priority_indication_with_nsapi_ie_t signalling_priority_indication_with_nsapi;
	gtpv1_higher_bitrates_than_16_mbps_flag_ie_t higher_bitrates_than_16_mbps_flag;
	gtpv1_selection_mode_with_nsapi_ie_t selection_mode_with_nsapi;
	gtpv1_local_home_network_id_with_nsapi_ie_t local_home_network_id_with_nsapi;
	gtpv1_ue_usage_type_ie_t ue_usage_type;
	gtpv1_extended_common_flag_2_ie_t extended_common_flag_2;
	gtpv1_ue_scef_pdn_connection_ie_t ue_scef_pdn_connection;
	gtpv1_iov_updates_counter_ie_t iov_updates_counter;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_sgsn_ctxt_rsp_t;

/*
 *  @brief : structure for gtpv1 RAN information relay Message
 */
typedef struct gtpv1_ran_info_relay_t {
	gtpv1_header_t header;
	gtpv1_ran_transparent_container_ie_t ran_transparent_container;
	gtpv1_rim_routing_addr_ie_t rim_addr;
	gtpv1_rim_routing_addr_disc_ie_t rim_addr_disc;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_ran_info_relay_t;

/*
 *  @brief : structure for gtpv1 UE registration query Request Message
 */
typedef struct gtpv1_ue_registration_query_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_ue_registration_query_req_t;

/*
 *  @brief : structure for gtpv1 UE registration query Response Message
 */
typedef struct gtpv1_ue_registration_query_rsp_t{
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_imsi_ie_t imsi;
	gtpv1_selected_plmn_id_ie_t plmn_id;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_ue_registration_query_rsp_t;

/*
 *  @brief : structure for gtpv1 MBMS notification Request Message
 */
typedef struct gtpv1_mbms_notification_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_nsapi_ie_t nsapi;
	gtpv1_end_user_address_ie_t end_user_address;
	gtpv1_apn_ie_t apn;
	gtpv1_gsn_addr_ie_t ggsn_addr_control_plane;
	gtpv1_mbms_protocol_config_options_ie_t mbms_protocol;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_mbms_notification_req_t;

/*
 *  @brief : structure for gtpv1 MBMS notification Response Message
 */
typedef struct gtpv1_mbms_notification_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_mbms_notification_rsp_t;

/*
 *  @brief : structure for gtpv1 Forward relocation Request Message
 */
typedef struct gtpv1_forward_relocation_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_teid_ie_t tunn_endpt_idnt_control_plane;
	gtpv1_ranap_cause_ie_t ranap_cause;
	gtpv1_packet_flow_id_ie_t packet_flow_id;
	gtpv1_chrgng_char_ie_t chrgng_char;
	gtpv1_mm_context_ie_t mm_context;
	gtpv1_pdp_context_ie_t pdp_context;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these gsn address will come
		-> SGSN Address for Control Plane
		-> Alternative GGSN Address for Control Plane
		-> Alternative GGSN Address for user traffic
		So it will based on the assumption of application in which order they want to send or accept
	*/
	gtpv1_gsn_addr_ie_t gsn_addr_1;
	gtpv1_gsn_addr_ie_t gsn_addr_2;
	gtpv1_gsn_addr_ie_t gsn_addr_3;
	gtpv1_target_identification_ie_t target_id;
	gtpv1_utran_transparent_container_ie_t utran_container;
	gtpv1_pdp_context_prioritization_ie_t pdp_context_prioritization;
	gtpv1_mbms_ue_context_ie_t mbms_ue_context;
	gtpv1_selected_plmn_id_ie_t plmn_id;
	gtpv1_bss_container_ie_t bss_container;
	gtpv1_cell_identification_ie_t cell_id;
	gtpv1_bssgp_cause_ie_t bssgp_cause;
	gtpv1_ps_handover_xid_param_ie_t xid_param;
	gtpv1_direct_tunnel_flag_ie_t direct_tunnel_flag;
	gtpv1_reliable_inter_rat_handover_info_ie_t inter_rat_handover;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these RFSP index will come
		-> subscribed rfsp index
		-> rfsp index in use
		So considered first as subscribed rfsp index and second as rfsp index in use
	*/
	gtpv1_rfsp_index_ie_t subscribed_rfsp_index;
	gtpv1_rfsp_index_ie_t rfsp_index_in_use;
	gtpv1_fqdn_ie_t co_located_ggsn_pgw_fqdn;
	gtpv1_evolved_allocation_retention_priority_II_ie_t evolved_allocation_retention_priority_II;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_csg_id_ie_t csg_id;
	gtpv1_csg_membership_indication_ie_t csg_member;
	gtpv1_ue_network_capability_ie_t ue_network_capability;
	gtpv1_ue_ambr_ie_t ue_ambr;
	gtpv1_apn_ambr_with_nsapi_ie_t apn_ambr_with_nsapi;
	gtpv1_signalling_priority_indication_with_nsapi_ie_t signalling_priority_indication_with_nsapi;
	gtpv1_higher_bitrates_than_16_mbps_flag_ie_t higher_bitrates_than_16_mbps_flag;
	gtpv1_additional_mm_ctxt_for_srvcc_ie_t add_mm_ctxt;
	gtpv1_additional_flags_for_srvcc_ie_t add_flag_srvcc;
	gtpv1_stn_sr_ie_t stn_sr;
	gtpv1_c_msisdn_ie_t c_msisdn;
	gtpv1_extended_ranap_cause_ie_t ext_ranap_cause;
	gtpv1_enodeb_id_ie_t enodeb_id;
	gtpv1_selection_mode_with_nsapi_ie_t selection_mode_with_nsapi;
	gtpv1_ue_usage_type_ie_t ue_usage_type;
	gtpv1_extended_common_flag_2_ie_t extended_common_flag_2;
	gtpv1_ue_scef_pdn_connection_ie_t ue_scef_pdn_connection;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_forward_relocation_req_t;

/*
 *  @brief : structure for gtpv1 Forward relocation Response Message
 */
typedef struct gtpv1_forward_relocation_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_teid_ie_t teid_control_plane;
	gtpv1_teid_data_2_ie_t teid_2;
	gtpv1_ranap_cause_ie_t ranap_cause;
	/* 
		As per the 3GPP spec TS29.060 V16.0.0 it is not clear in which order these gsn address will come
		-> SGSN Address for control plane
		-> SGSN Address for user traffic
		So considered first as SGSN Address for control plane and second as SGSN Address for user traffic
	*/
	gtpv1_gsn_addr_ie_t sgsn_addr_control_plane;
	gtpv1_gsn_addr_ie_t sgsn_addr_user_traffic;
	gtpv1_utran_transparent_container_ie_t utran_container;
	gtpv1_rab_setup_info_ie_t rab_setup_info;
	gtpv1_rab_setup_info_ie_t add_rab_setup_info;
	gtpv1_sgsn_number_ie_t sgsn_number;
	gtpv1_bss_container_ie_t bss_container;
	gtpv1_bssgp_cause_ie_t bssgp_cause;
	gtpv1_list_of_setup_pfcs_ie_t list_pfcs;
	gtpv1_extended_ranap_cause_ie_t ext_ranap_cause;
	gtpv1_node_identifier_ie_t node_id;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_forward_relocation_rsp_t;

/*
 *  @brief : structure for gtpv1 MS information change notification Request Message
 */
typedef struct gtpv1_ms_info_change_notification_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_nsapi_ie_t linked_nsapi;
	gtpv1_rat_type_ie_t rat_type;
	gtpv1_user_location_information_ie_t user_location_information;
	gtpv1_imei_ie_t imei_sv;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_user_csg_information_ie_t user_csg_information;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_ms_info_change_notification_req_t;

/*
 *  @brief : structure for gtpv1 MS information change notification Response Message
 */
typedef struct gtpv1_ms_info_change_notification_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_imsi_ie_t imsi;
	gtpv1_nsapi_ie_t linked_nsapi;
	gtpv1_imei_ie_t imei_sv;
	gtpv1_ms_info_change_reporting_action_ie_t ms_info_change_reporting_action;
	gtpv1_csg_information_reporting_action_ie_t csg_information_reporting_action;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_ms_info_change_notification_rsp_t;

/*
 *  @brief : structure for gtpv1 Identification Request Message
 */
typedef struct gtpv1_identification_req_t {
	gtpv1_header_t header;
	gtpv1_routing_area_identity_ie_t routing_area_identity;
	gtpv1_packet_tmsi_ie_t packet_tmsi;
	gtpv1_p_tmsi_signature_ie_t p_tmsi_signature;
	gtpv1_gsn_addr_ie_t sgsn_addr_control_plane;
	gtpv1_hop_counter_ie_t hop_counter;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_identification_req_t;

/*
 *  @brief : structure for gtpv1 Identification Response Message
 */
typedef struct gtpv1_identification_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_imsi_ie_t imsi;
	gtpv1_auth_triplet_ie_t auth_triplet;
	gtpv1_auth_quintuplet_ie_t auth_quintuplet;
	gtpv1_ue_usage_type_ie_t ue_usage_type;
	gtpv1_iov_updates_counter_ie_t iov_updates_counter;
} gtpv1_identification_rsp_t;

/*
 *  @brief : structure for gtpv1 relocation cancel Request Message
 */
typedef struct gtpv1_relocation_cancel_req_t {
	gtpv1_header_t header;
	gtpv1_imsi_ie_t imsi;
	gtpv1_imei_ie_t imei_sv;
	gtpv1_extended_common_flag_ie_t extended_common_flag;
	gtpv1_extended_ranap_cause_ie_t ext_ranap_cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_relocation_cancel_req_t;

/*
 *  @brief : structure for gtpv1 relocation cancel Response Message
 */
typedef struct gtpv1_relocation_cancel_rsp_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_relocation_cancel_rsp_t;

/*
 *  @brief : structure for gtpv1 Forward relocation complete acknowledgement Message
 */
typedef struct gtpv1_forward_relocation_complete_ack_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_forward_relocation_complete_ack_t;

/*
 *  @brief : structure for gtpv1 Forward relocation complete Message
 */
typedef struct gtpv1_forward_relocation_complete_t {
	gtpv1_header_t header;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_forward_relocation_complete_t;

/*
 *  @brief : structure for gtpv1 forward srns context acknowledgement Message
 */
typedef struct gtpv1_forward_srns_context_ack_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_forward_srns_context_ack_t;

/*
 *  @brief : structure for gtpv1 forward srns context Message
 */
typedef struct gtpv1_forward_srns_ctxt_t {
	gtpv1_header_t header;
	gtpv1_rab_context_ie_t rab_context;
	gtpv1_src_rnc_pdcp_ctxt_info_ie_t pdcp_ctxt;
	gtpv1_pdu_numbers_ie_t pdu_num;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_forward_srns_ctxt_t;

/*
 *  @brief : structure for gtpv1 sgsn context acknowledgement Message
 */
typedef struct gtpv1_sgsn_context_ack_t {
	gtpv1_header_t header;
	gtpv1_cause_ie_t cause;
	gtpv1_teid_data_2_ie_t teid_2;
	gtpv1_gsn_addr_ie_t sgsn_addr_user_traffic;
	gtpv1_sgsn_number_ie_t sgsn_number;
	gtpv1_node_identifier_ie_t node_id;
	gtpv1_private_extension_ie_t private_extension;
} gtpv1_sgsn_context_ack_t;

/*
 *  @brief : structure for gtpv1 supported extension headers notification Message
 */
typedef struct gtpv1_supported_extension_headers_notification_t {
	gtpv1_header_t header;
	gtpv1_extension_header_type_list_ie_t ext_header_list;
} gtpv1_supported_extension_headers_notification_t;

#ifdef __cplusplus
}
#endif

#endif /*__GTPV1_MESSAGES_H__*/
