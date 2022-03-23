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

#ifndef __GTPV1_IES_ENCODER_H__
#define __GTPV1_IES_ENCODER_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "enc_dec_bits.h"
#include "gtpv1_ies.h"

/*
 * @brief  : encode gtpv1 header to buffer.
 * @param  : value, gtpv1_header_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_header(const gtpv1_header_t *value, uint8_t *buf);

/*
 * @brief  : encode ie header to buffer.
 * @param  : value, gtpv1_ie_header_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ie_header(const gtpv1_ie_header_t *value, uint8_t *buf);

/*
 * @brief  : encode IMSI to buffer.
 * @param  : val, IMSI value which will be encoded
 * @param  : len, length of IMSI.
 * @param  : imsi, store imsi after encoding.
 * @return : nothing.
 */
void encode_imsi(uint64_t val, int len, uint8_t *imsi);

/*
 * @brief  : encode IMSI IE to buffer.
 * @param  : value, gtpv1_imsi_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_imsi_ie(const gtpv1_imsi_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode selection mode IE to buffer.
 * @param  : value, gtpv1_selection_mode_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_selection_mode_ie(const gtpv1_selection_mode_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode teid IE to buffer.
 * @param  : value, gtpv1_teid_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_teid_ie(const gtpv1_teid_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode NASAPI IE to buffer.
 * @param  : value, gtpv1_nsapi_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_nsapi_ie(const gtpv1_nsapi_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode charging characteristics IE to buffer.
 * @param  : value, gtpv1_chrgng_char_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_chrgng_char_ie(const gtpv1_chrgng_char_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode pdp address to buffer.
 * @param  : value, gtpv1_pdp_addr_t structure which will be encoded
 * @param  : buf, buffer to store encoded values
 * @param  : encoded, total bytes previously encoded
 * @param  : length, total length of pdp address
 * @param  : number, pdp type number
 * @return : success 'number of encoded bytes', failure '0'.
 */
int16_t encode_pdp_address(const gtpv1_pdp_addr_t *value, uint8_t *buf, uint16_t encoded, uint16_t length, uint8_t number);

/*
 * @brief  : encode end user address IE to buffer.
 * @param  : value, gtpv1_end_user_address_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_end_user_address_ie(const gtpv1_end_user_address_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode Access Point Name IE to buffer.
 * @param  : value, gtpv1_apn_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_apn_ie(const gtpv1_apn_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode gsn address to buffer.
 * @param  : value, gtpv1_gsn_addr_t structure which will be encoded
 * @param  : buf, buffer to store encoded values
 * @param  : encoded, total bytes previously encoded
 * @param  : length, total length of gsn address
 * @return : success 'number of encoded bytes', failure '0'.
 */
int16_t encode_gsn_address(const gtpv1_gsn_addr_t *value, uint8_t *buf, uint16_t encoded, uint16_t length);

/*
 * @brief  : encode gsn address IE to buffer.
 * @param  : value, gtpv1_gsn_addr_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_gsn_address_ie(const gtpv1_gsn_addr_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode msisdn IE to buffer.
 * @param  : value, gtpv1_msisdn_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_msisdn_ie(const gtpv1_msisdn_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode qos profile data to buffer.
 * @param  : value, gtpv1_qos_t structure which will be encoded
 * @param  : buf, buffer to store encoded values
 * @param  : encoded, total bytes previously encoded
 * @param  : length, total length of qos
 * @return : number of encoded bytes.
 */
int16_t encode_qos(const gtpv1_qos_t *value, uint8_t *buf, uint16_t encoded, uint16_t length);

/*
 * @brief  : encode qos IE to buffer.
 * @param  : value, gtpv1_qos_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_qos_ie(const gtpv1_qos_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode TFT IE to buffer.
 * @param  : value, gtpv1_traffic_flow_tmpl_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_traffic_flow_tmpl_ie(const gtpv1_traffic_flow_tmpl_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode IMEI IE to buffer.
 * @param  : value, gtpv1_imei_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_imei_ie(const gtpv1_imei_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode RAT type IE to buffer.
 * @param  : value, gtpv1_rat_type_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_rat_type_ie(const gtpv1_rat_type_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode routing area identity value to buffer.
 * @param  : value, gtpv1_routing_area_identity_ie_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @param  : encoded, encoded bist till now.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_routing_area_identity_value(gtpv1_routing_area_identity_value_t *value, uint8_t *buf, uint16_t encoded);

/*
 * @brief  : encode routing area identity IE to buffer.
 * @param  : value, gtpv1_routing_area_identity_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_routing_area_identity_ie(gtpv1_routing_area_identity_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode Trace reference IE to buffer.
 * @param  : value, gtpv1_trace_reference_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_trace_reference_ie(const gtpv1_trace_reference_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode trace type IE to buffer.
 * @param  : value, gtpv1_trace_type_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_trace_type_ie(const gtpv1_trace_type_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode trigger ID IE to buffer.
 * @param  : value, gtpv1_trigger_id_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_trigger_id_ie(const gtpv1_trigger_id_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode omc identity IE to buffer.
 * @param  : value, gtpv1_omc_identity_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_omc_identity_ie(const gtpv1_omc_identity_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode user location information IE to buffer.
 * @param  : value, gtpv1_user_location_information_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_user_location_information_ie(gtpv1_user_location_information_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode ms time zone IE to buffer.
 * @param  : value, gtpv1_ms_time_zone_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ms_time_zone_ie(const gtpv1_ms_time_zone_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode camel charging information container IE to buffer.
 * @param  : value, gtpv1_camel_charging_information_container_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_camel_charging_information_container_ie(const gtpv1_camel_charging_information_container_ie_t *value, 
		uint8_t *buf);

/*
 * @brief  : encode additional trace information IE to buffer.
 * @param  : value, gtpv1_additional_trace_information_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_additional_trace_information_ie(const gtpv1_additional_trace_information_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode correlation ID IE to buffer.
 * @param  : value, gtpv1_correlation_id_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_correlation_id_ie(const gtpv1_correlation_id_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode user csg information IE to buffer.
 * @param  : value, gtpv1_user_csg_information_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_user_csg_information_ie(gtpv1_user_csg_information_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode signalling priority indication IE to buffer.
 * @param  : value, gtpv1_signalling_priority_indication_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_signalling_priority_indication_ie(const gtpv1_signalling_priority_indication_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode cn operator selction entity IE to buffer.
 * @param  : value, gtpv1_cn_operator_selection_entity_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_cn_operator_selection_entity_ie(const gtpv1_cn_operator_selection_entity_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode mapped UE usage type IE to buffer.
 * @param  : value, gtpv1_mapped_ue_usage_type_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_mapped_ue_usage_type_ie(const gtpv1_mapped_ue_usage_type_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode up function selection indication IE to buffer.
 * @param  : value, gtpv1_up_function_selection_indication_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_up_function_selection_indication_ie(const gtpv1_up_function_selection_indication_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode cause IE to buffer.
 * @param  : value, gtpv1_cause_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_cause_ie(const gtpv1_cause_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode reordering req IE to buffer.
 * @param  : value, gtpv1_reordering_req_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_reordering_req_ie(const gtpv1_reordering_req_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode recovery IE to buffer.
 * @param  : value, gtpv1_recovery_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_recovery_ie(const gtpv1_recovery_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode charging ID IE to buffer.
 * @param  : value, gtpv1_charging_id_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_charging_id_ie(const gtpv1_charging_id_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode protocol config option to buffer.
 * @param  : value, gtpv1_protocol_config_options_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_protocol_config_options_ie(const gtpv1_protocol_config_options_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode charging gateway address IE to buffer.
 * @param  : value, gtpv1_charging_gateway_addr_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_charging_gateway_addr_ie(const gtpv1_charging_gateway_addr_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode common flag IE to buffer.
 * @param  : value, gtpv1_common_flag_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_common_flag_ie(const gtpv1_common_flag_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode apn restriction IE to buffer.
 * @param  : value, gtpv1_apn_restriction_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_apn_restriction_ie(const gtpv1_apn_restriction_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode ms info change reporting action IE to buffer.
 * @param  : value, gtpv1_ms_info_change_reporting_action_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ms_info_change_reporting_action_ie(const gtpv1_ms_info_change_reporting_action_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode bearer control mode IE to buffer.
 * @param  : value, gtpv1_bearer_control_mode_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_bearer_control_mode_ie(const gtpv1_bearer_control_mode_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode evolved allocation retention priority 1 IE to buffer.
 * @param  : value, gtpv1_evolved_allocation_retention_priority_1_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_evolved_allocation_retention_priority_1_ie(const gtpv1_evolved_allocation_retention_priority_1_ie_t *value, 
		uint8_t *buf);

/*
 * @brief  : encode extended common flag IE to buffer.
 * @param  : value, gtpv1_extended_common_flag_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_extended_common_flags_ie(const gtpv1_extended_common_flag_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode csg information reporting action IE to buffer.
 * @param  : value, gtpv1_csg_information_reporting_action_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_csg_information_reporting_action_ie(const gtpv1_csg_information_reporting_action_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode APN AMBR IE to buffer.
 * @param  : value, gtpv1_apn_ambr_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_apn_ambr_ie(const gtpv1_apn_ambr_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode ggsn back off time IE to buffer.
 * @param  : value, gtpv1_ggsn_back_off_time_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ggsn_back_off_time_ie(const gtpv1_ggsn_back_off_time_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode extended common flag 2 IE to buffer.
 * @param  : value, gtpv1_extended_common_flag_2_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_extended_common_flag_2_ie(const gtpv1_extended_common_flag_2_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode private extension IE to buffer.
 * @param  : value, gtpv1_private_extension_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_private_extension_ie(const gtpv1_private_extension_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode teardown indication IE to buffer.
 * @param  : value, gtpv1_teardown_ind_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_teardown_ind_ie(const gtpv1_teardown_ind_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode uli timestamp IE to buffer.
 * @param  : value, gtpv1_uli_timestamp_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_uli_timestamp_ie(const gtpv1_uli_timestamp_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode direct tunnel flag IE to buffer.
 * @param  : value, gtpv1_direct_tunnel_flag_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_direct_tunnel_flag_ie(const gtpv1_direct_tunnel_flag_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode map cause IE to buffer.
 * @param  : value, gtpv1_map_cause_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_map_cause_ie(const gtpv1_map_cause_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode ms not rechable reason IE to buffer.
 * @param  : value, gtpv1_ms_not_rechable_reason_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ms_not_rechable_reason_ie(const gtpv1_ms_not_rechable_reason_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode temporary logical link identifier IE to buffer.
 * @param  : value, gtpv1_temporary_logical_link_identifier_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_temporary_logical_link_identifier_ie(const gtpv1_temporary_logical_link_identifier_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode packet tmsi IE to buffer.
 * @param  : value, gtpv1_packet_tmsi_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_packet_tmsi_ie(const gtpv1_packet_tmsi_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode p tmsi signature IE to buffer.
 * @param  : value, gtpv1_p_tmsi_signature_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_p_tmsi_signature_ie(const gtpv1_p_tmsi_signature_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode ms validate IE to buffer.
 * @param  : value, gtpv1_ms_validated_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ms_validated_ie(const gtpv1_ms_validated_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode sgsn number IE to buffer.
 * @param  : value, gtpv1_sgsn_number_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_sgsn_number_ie(const gtpv1_sgsn_number_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode hop counter IE to buffer.
 * @param  : value, gtpv1_hop_counter_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_hop_counter_ie(const gtpv1_hop_counter_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode rab context IE to buffer.
 * @param  : value, gtpv1_rab_context_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_rab_context_ie(const gtpv1_rab_context_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode radio priority sms IE to buffer.
 * @param  : value, gtpv1_radio_priority_sms_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_radio_priority_sms_ie(const gtpv1_radio_priority_sms_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode radio priority IE to buffer.
 * @param  : value, gtpv1_radio_priority_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_radio_priority_ie(const gtpv1_radio_priority_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode packet flow ID IE to buffer.
 * @param  : value, gtpv1_packet_flow_id_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_packet_flow_id_ie(const gtpv1_packet_flow_id_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode radio priority lcs IE to buffer.
 * @param  : value, gtpv1_radio_priority_lcs_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_radio_priority_lcs_ie(const gtpv1_radio_priority_lcs_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode gtpv1 used cipher value umts keys and quintuplets to buffer
 * @param  : value, gtpv1_used_cipher_value_umts_keys_and_quintuplets_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @param  : encoded, no of bits already encoded
 * @param  : seq_mode, value of seq_mode
 * @return : success 'number of 'encoded bits'
 */
int16_t encode_gtpv1_used_cipher_value_umts_keys_and_quintuplets(
		const gtpv1_used_cipher_value_umts_keys_and_quintuplets_t *value, uint8_t *buf, uint16_t encoded,
		uint8_t seq_mode);

/*
 * @brief  : encode gtpv1 gsm keys and triplet
 * @param  : value, gtpv1_gsm_key_and_triplet_t structure which will be encoded
 * @param  : buf, buffer to store encoded values
 * @param  : encoded, no of bits already encoded
 * @param  : seq_mode, value of seq_mode
 * @return : success 'number of 'encoded bits'
 */
int16_t encode_gtpv1_gsm_keys_and_triplet(gtpv1_gsm_key_and_triplet_t *value, uint8_t *buf, uint16_t encoded, uint8_t seq_mode);

/*
 * @brief  : encode gtpv1 umts keys and quintuplets
 * @param  : value, gtpv1_umts_keys_and_quintuplets_t structure which will be encoded
 * @param  : buf, buffer to store encoded values
 * @param  : encoded, no of bits already encoded
 * @param  : seq_mode, value of seq_mode
 * @return : success 'number of 'encoded bits'
 */
int16_t encode_gtpv1_umts_keys_and_quintuplets(gtpv1_umts_keys_and_quintuplets_t *value, uint8_t *buf, uint16_t encoded, uint8_t seq_mode);

/*
 * @brief  : encode gtpv1 gsm keys and umts quintuplets
 * @param  : value, gtpv1_gsm_keys_and_umts_quintuplets_t structure which will be encoded
 * @param  : buf, buffer to store encoded values
 * @param  : encoded, no of bits already encoded
 * @param  : seq_mode, value of seq_mode
 * @return : success 'number of 'encoded bits'
 */
int16_t encode_gtpv1_gsm_keys_and_umts_quintuplets(gtpv1_gsm_keys_and_umts_quintuplets_t *value, uint8_t *buf, uint16_t encoded, uint8_t seq_mode);

/*
 * @brief  : encode gtpv1 ms network capability value
 * @param  : value, gtpv1_ms_network_capability_value_t structure which will be encoded
 * @param  : buf, buffer to store encoded values
 * @param  : encoded, no of bits already encoded
 * @return : success 'number of 'encoded bits'
 */
int16_t encode_ms_network_capability_value(const gtpv1_ms_network_capability_value_t *value, uint8_t *buf, 
		uint16_t encoded);

/*
 * @brief  : encode mm context IE to buffer.
 * @param  : value, gtpv1_mm_context_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_mm_context_ie(gtpv1_mm_context_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode pdp context IE to buffer.
 * @param  : value, gtpv1_pdp_context_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_pdp_context_ie(const gtpv1_pdp_context_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode pdp context prioritization IE to buffer.
 * @param  : value, gtpv1_pdp_context_prioritization_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_pdp_context_prioritization_ie(const gtpv1_pdp_context_prioritization_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode mbms ue context IE to buffer.
 * @param  : value, gtpv1_mbms_ue_context_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_mbms_ue_context_ie(const gtpv1_mbms_ue_context_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode rfsp index IE to buffer.
 * @param  : value, gtpv1_rfsp_index_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_rfsp_index_ie(const gtpv1_rfsp_index_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode fqdn ID IE to buffer.
 * @param  : value, gtpv1_fqdn_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_fqdn_ie(const gtpv1_fqdn_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode evolved allocation retention priority II IE to buffer.
 * @param  : value, gtpv1_evolved_allocation_retention_priority_II_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_evolved_allocation_retention_priority_II_ie(
		const gtpv1_evolved_allocation_retention_priority_II_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode ue network capability IE to buffer.
 * @param  : value, gtpv1_ue_network_capability_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ue_network_capability_ie(const gtpv1_ue_network_capability_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode UE AMBR ID IE to buffer.
 * @param  : value, gtpv1_ue_ambr_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ue_ambr_ie(const gtpv1_ue_ambr_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode APN AMBR with nsapi IE to buffer.
 * @param  : value, gtpv1_apn_ambr_with_nsapi_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_apn_ambr_with_nsapi_ie(const gtpv1_apn_ambr_with_nsapi_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode signalling priority indication with nsapi IE to buffer.
 * @param  : value, gtpv1_signalling_priority_indication_with_nsapi_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_signalling_priority_indication_with_nsapi_ie(
		const gtpv1_signalling_priority_indication_with_nsapi_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode higher bitrates than 16 mbps flag IE to buffer.
 * @param  : value, gtpv1_higher_bitrates_than_16_mbps_flag_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(const gtpv1_higher_bitrates_than_16_mbps_flag_ie_t *value, 
											uint8_t *buf);

/*
 * @brief  : encode selection mode with nsapi IE to buffer.
 * @param  : value, gtpv1_selection_mode_with_nsapi_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_selection_mode_with_nsapi_ie(const gtpv1_selection_mode_with_nsapi_ie_t *value, 
											uint8_t *buf);

/*
 * @brief  : encode local home network id with nsapi IE to buffer.
 * @param  : value, gtpv1_local_home_network_id_with_nsapi_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_local_home_network_id_with_nsapi_ie(const gtpv1_local_home_network_id_with_nsapi_ie_t *value, 
											uint8_t *buf);

/*
 * @brief  : encode UE usage type IE to buffer.
 * @param  : value, gtpv1_ue_usage_type_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ue_usage_type_ie(const gtpv1_ue_usage_type_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode UE scef pdn connection IE to buffer.
 * @param  : value, gtpv1_ue_scef_pdn_connection_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ue_scef_pdn_connection_ie(const gtpv1_ue_scef_pdn_connection_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode IOV updates counter IE to buffer.
 * @param  : value, gtpv1_iov_updates_counter_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_iov_updates_counter_ie(const gtpv1_iov_updates_counter_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode RAN transparent container IE to buffer.
 * @param  : value, gtpv1_ran_transparent_container_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ran_transparent_container_ie(const gtpv1_ran_transparent_container_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode RIM routing address IE to buffer.
 * @param  : value, gtpv1_rim_routing_addr_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_rim_routing_addr_ie(const gtpv1_rim_routing_addr_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode RIM routing address disc IE to buffer.
 * @param  : value, gtpv1_rim_routing_addr_disc_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_rim_routing_addr_disc_ie(const gtpv1_rim_routing_addr_disc_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode selected plmn ID IE to buffer.
 * @param  : value, gtpv1_selected_plmn_id_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_selected_plmn_id_ie(gtpv1_selected_plmn_id_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode mbms protocol config option ID IE to buffer.
 * @param  : value, gtpv1_mbms_protocol_config_options_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_mbms_protocol_config_options_ie(const gtpv1_mbms_protocol_config_options_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode teid data 2 IE to buffer.
 * @param  : value, gtpv1_teid_2_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_teid_data_2_ie(const gtpv1_teid_data_2_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode RANAP cause IE to buffer.
 * @param  : value, gtpv1_ranap_cause_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ranap_cause_ie(const gtpv1_ranap_cause_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode Target identification IE to buffer.
 * @param  : value, gtpv1_target_identification_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_target_identification_ie(gtpv1_target_identification_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode utran transparent container IE to buffer.
 * @param  : value, gtpv1_utran_transparent_container_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_utran_transparent_container_ie(const gtpv1_utran_transparent_container_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode rab setup info IE to buffer.
 * @param  : value, gtpv1_rab_setup_info_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_rab_setup_info_ie(const gtpv1_rab_setup_info_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode BSS container IE to buffer.
 * @param  : value, gtpv1_bss_container_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_bss_container_ie(const gtpv1_bss_container_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode cell identification IE to buffer.
 * @param  : value, gtpv1_cell_identification_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_cell_identification_ie(gtpv1_cell_identification_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode bssgp cause IE to buffer.
 * @param  : value, gtpv1_bssgp_cause_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_bssgp_cause_ie(const gtpv1_bssgp_cause_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode list of setup pfcs IE to buffer.
 * @param  : value, gtpv1_list_of_setup_pfcs_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_list_of_setup_pfcs_ie(const gtpv1_list_of_setup_pfcs_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode ps handover xid param IE to buffer.
 * @param  : value, gtpv1_ps_handover_xid_param_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_ps_handover_xid_param_ie(const gtpv1_ps_handover_xid_param_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode reliable inter rat handover info IE to buffer.
 * @param  : value, gtpv1_reliable_inter_rat_handover_info_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_reliable_inter_rat_handover_info_ie(const gtpv1_reliable_inter_rat_handover_info_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode CSG ID IE to buffer.
 * @param  : value, gtpv1_csg_id_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_csg_id_ie(const gtpv1_csg_id_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode csg membership indication IE to buffer.
 * @param  : value, gtpv1_csg_membership_indication_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_csg_membership_indication_ie(const gtpv1_csg_membership_indication_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode additional mm ctxt for srvcc IE to buffer.
 * @param  : value, gtpv1_additional_mm_ctxt_for_srvcc_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_additional_mm_ctxt_for_srvcc_ie(const gtpv1_additional_mm_ctxt_for_srvcc_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode additional flags for srvcc IE to buffer.
 * @param  : value, gtpv1_additional_flags_for_srvcc_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_additional_flags_for_srvcc_ie(const gtpv1_additional_flags_for_srvcc_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode stn sr IE to buffer.
 * @param  : value, gtpv1_stn_sr_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_stn_sr_ie(const gtpv1_stn_sr_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode c msisdn IE to buffer.
 * @param  : value, gtpv1_c_msisdn_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_c_msisdn_ie(const gtpv1_c_msisdn_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode extended RANAP cause IE to buffer.
 * @param  : value, gtpv1_extended_ranap_cause_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_extended_ranap_cause_ie(const gtpv1_extended_ranap_cause_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode enodeb ID IE to buffer.
 * @param  : value, gtpv1_enodeb_id_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_enodeb_id_ie(gtpv1_enodeb_id_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode node identifier IE to buffer.
 * @param  : value, gtpv1_node_identifier_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_node_identifier_ie(const gtpv1_node_identifier_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode auth triplet IE value to buffer.
 * @param  : value, gtpv1_auth_triplet_value_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @param  : encoded, number of bits encoded
 * @return : number of encoded bytes
 */
int16_t encode_auth_triplet_value(const gtpv1_auth_triplet_value_t *value, uint8_t *buf, uint16_t encoded);

/*
 * @brief  : encode auth triplet IE to buffer.
 * @param  : value, gtpv1_auth_triplet_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_auth_triplet_ie(const gtpv1_auth_triplet_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode auth quintuplet IE value to buffer.
 * @param  : value, gtpv1_auth_quintuplet_value_t structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @param  : encoded, number of bits encoded
 * @return : number of encoded bytes
 */
int16_t encode_auth_quintuplet_value(const gtpv1_auth_quintuplet_value_t *value, uint8_t *buf, uint16_t encoded);

/*
 * @brief  : encode auth quintuplet IE to buffer.
 * @param  : value, gtpv1_auth_quintuplet_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_auth_quintuplet_ie(const gtpv1_auth_quintuplet_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode src rnc pdcp ctxt info IE to buffer.
 * @param  : value, gtpv1_src_rnc_pdcp_ctxt_info_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_src_rnc_pdcp_ctxt_info_ie(const gtpv1_src_rnc_pdcp_ctxt_info_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode PDU number IE to buffer.
 * @param  : value, gtpv1_pdu_number_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_pdu_numbers_ie(const gtpv1_pdu_numbers_ie_t *value, uint8_t *buf);

/*
 * @brief  : encode extension header type list IE to buffer.
 * @param  : value, gtpv1_extension_header_type_list_ie_t  structure which will be encoded
 * @param  : buf, buffer to store encoded values.
 * @return : success 'number of encoded bytes', failure '-1'.
 */
int16_t encode_gtpv1_extension_header_type_list_ie(const gtpv1_extension_header_type_list_ie_t *value, uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif /*__GTPV1_IES_ENCODER_H__*/
