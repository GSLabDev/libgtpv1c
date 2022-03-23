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

#ifndef __GTPV1_IES_DECODER_H__
#define __GTPV1_IES_DECODER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "enc_dec_bits.h"
#include "gtpv1_ies.h"

#define SKIP_SEQ_MODE 2

/*
 * @brief  : get length of TV type ie structure
 * @param  : type, ie type value
 * @return : success 'ie length', failure '-1'.
 */
int get_length(uint8_t type);

/*
 * @brief  : decodes gtpv1 header from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_header_t which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_header(const uint8_t *buf, gtpv1_header_t *value);

/*
 * @brief  : decodes ie header from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ie_header_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ie_header(const uint8_t *buf, gtpv1_ie_header_t *value);

/*
 * @brief  : decodes gtpv1 teid IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_teid_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_teid_ie(const uint8_t *buf, gtpv1_teid_ie_t *value);

/*
 * @brief  : decodes gtpv1 nsapi IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_nsapi_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_nsapi_ie(const uint8_t *buf, gtpv1_nsapi_ie_t *value);

/*
 * @brief  : decodes Access Point Name IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_apn_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_apn_ie(const uint8_t *buf, gtpv1_apn_ie_t *value);

/*
 * @brief  : decodes gsn address from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_gsn_addr_t structure which will store decoded values
 * @param  : total_decoded, total bytes previously decoded
 * @param  : length, total length of gsn address
 * @return : success 'number of decoded bytes', failure '0'.
 */
int16_t decode_gsn_address(const uint8_t *buf, gtpv1_gsn_addr_t *value, uint16_t total_decoded, uint16_t length);

/*
 * @brief  : decodes gtpv1 GSN Address IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_gsn_addr_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_gsn_address_ie(const uint8_t *buf, gtpv1_gsn_addr_ie_t *value);

/*
 * @brief  : decodes qos profile data from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_qos_t structure which will store decoded values
 * @param  : total_decoded, total bytes previously decoded
 * @param  : length, total length of qos
 * @return : number of decoded bytes.
 */
int16_t decode_qos(const uint8_t *buf, gtpv1_qos_t *value, uint16_t total_decoded, uint16_t length);

/*
 * @brief  : decodes gtpv1 qos IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_qos_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_qos_ie(const uint8_t *buf, gtpv1_qos_ie_t *value);

/*
 * @brief  : decodes gtpv1 cause IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_casue_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_cause_ie(const uint8_t *buf, gtpv1_cause_ie_t *value);

/*
 * @brief  : decodes gtpv1 selection mode IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_selection_mode_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_selection_mode_ie(const uint8_t *buf, gtpv1_selection_mode_ie_t *value);
  
/*
 * @brief  : decodes gtpv1 charging characteristics IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_chrgng_char_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_chrgng_char_ie(const uint8_t *buf, gtpv1_chrgng_char_ie_t *value);

/*
 * @brief  : decodes gtpv1 msisdn IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_msisdn_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_msisdn_ie(const uint8_t *buf, gtpv1_msisdn_ie_t *value);

/*
 * @brief  : decodes gtpv1 imei IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_imei_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_imei_ie(const uint8_t *buf, gtpv1_imei_ie_t *value);

/*
 * @brief  : decodes gtpv1 traffic flow templet IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_traffic_flow_tmpl_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_traffic_flow_tmpl_ie(const uint8_t *buf, gtpv1_traffic_flow_tmpl_ie_t *value);

/*
 * @brief  : decodes gtpv1 rat type IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_rat_type_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_rat_type_ie(const uint8_t *buf, gtpv1_rat_type_ie_t *value);

/*
 * @brief  : decode IMSI value from buffer.
 * @param  : buf, buffer to decode
 * @param  : len, length of IMSI.
 * @param  : imsi, store imsi after decoding.
 * @return : nothing.
 */
void decode_imsi(const uint8_t *buf, int len, uint64_t *imsi);

/*
 * @brief  : decodes gtpv1 imsi IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_imsi_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_imsi_ie(const uint8_t *buf, gtpv1_imsi_ie_t *value);

/*
 * @brief  : decodes gtpv1 reordering request IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_reordering_req_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_reordering_req_ie(const uint8_t *buf, gtpv1_reordering_req_ie_t *value);

/*
 * @brief  : decodes gtpv1 recovery IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_recovery_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_recovery_ie(const uint8_t *buf, gtpv1_recovery_ie_t *value);

/*
 * @brief  : decodes gtpv1 charging ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_charging_id_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_charging_id_ie(const uint8_t *buf, gtpv1_charging_id_ie_t *value);

/*
 * @brief  : decodes pdp address from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdp_addr_t structure which will store decoded values
 * @param  : total_decoded, total bytes previously decoded
 * @param  : length, total length of pdp address
 * @param  : number, pdp type number
 * @return : success 'number of decoded bytes', failure '0'.
 */
int16_t decode_pdp_address(const uint8_t *buf, gtpv1_pdp_addr_t *value, uint16_t total_decoded, uint16_t length, uint8_t number);

/*
 * @brief  : decodes gtpv1 end user address IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_end_user_address_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_end_user_address_ie(const uint8_t *buf, gtpv1_end_user_address_ie_t *value);

/*
 * @brief  : decodes gtpv1 protocol config option IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_protocol_config_options_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_protocol_config_options_ie(const uint8_t *buf, gtpv1_protocol_config_options_ie_t *value);

/*
 * @brief  : decodes gtpv1 charging gateway address IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_charging_gateway_addr_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_charging_gateway_addr_ie(const uint8_t *buf, gtpv1_charging_gateway_addr_ie_t *value);

/*
 * @brief  : decodes gtpv1 common flag IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_common_flag_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_common_flag_ie(const uint8_t *buf, gtpv1_common_flag_ie_t *value);

/*
 * @brief  : decodes gtpv1 apn restriction IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_apn_restriction_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_apn_restriction_ie(const uint8_t *buf, gtpv1_apn_restriction_ie_t *value);

/*
 * @brief  : decodes gtpv1 ms info change reporting action IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ms_info_change_reporting_action_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ms_info_change_reporting_action_ie(const uint8_t *buf, gtpv1_ms_info_change_reporting_action_ie_t *value);

/*
 * @brief  : decodes gtpv1 bearer control mode IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_bearer_control_mode_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_bearer_control_mode_ie(const uint8_t *buf, gtpv1_bearer_control_mode_ie_t *value);

/*
 * @brief  : decodes gtpv1 evolved allocation retention priority 1 IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_evolved_allocation_retention_priority_1_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_evolved_allocation_retention_priority_1_ie(const uint8_t *buf, gtpv1_evolved_allocation_retention_priority_1_ie_t *value);

/*
 * @brief  : decodes gtt extended common flag IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_extended_common_flag_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_extended_common_flag_ie(const uint8_t *buf, gtpv1_extended_common_flag_ie_t *value);

/*
 * @brief  : decodes gtpv1 csg information reporting action IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_csg_information_reporting_action_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_csg_information_reporting_action_ie(const uint8_t *buf, gtpv1_csg_information_reporting_action_ie_t *value);

/*
 * @brief  : decodes gtpv1 apn ambr ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_apn_ambr_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_apn_ambr_ie(const uint8_t *buf, gtpv1_apn_ambr_ie_t *value);

/*
 * @brief  : decodes gtpv1 ggsn back off IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ggsn_back_off_time_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ggsn_back_off_time_ie(const uint8_t *buf, gtpv1_ggsn_back_off_time_ie_t *value);

/*
 * @brief  : decodes gtpv1 extended common flag 2 IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_extended_common_flag_2_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_extended_common_flag_2_ie(const uint8_t *buf, gtpv1_extended_common_flag_2_ie_t *value);

/*
 * @brief  : decodes gtpv1 private extension IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_private_extension_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_private_extension_ie(const uint8_t *buf, gtpv1_private_extension_ie_t *value);

/*
 * @brief  : decodes routing area identity value from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_routing_area_identity_ie_t structure which will store decoded values
 * @param  : total_decoded, total bits already decoded
 * @return : number of decoded bytes
 */
int16_t decode_routing_area_identity_value(const uint8_t *buf, gtpv1_routing_area_identity_value_t *value, uint16_t total_decoded);

/*
 * @brief  : decodes gtpv1 routing area identity IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_routing_area_identity_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_routing_area_identity_ie(const uint8_t *buf, gtpv1_routing_area_identity_ie_t *value);

/*
 * @brief  : decodes gtpv1 trace reference IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_trace_reference_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_trace_reference_ie(const uint8_t *buf, gtpv1_trace_reference_ie_t *value);

/*
 * @brief  : decodes gtpv1 trace type IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_trace_type_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_trace_type_ie(const uint8_t *buf, gtpv1_trace_type_ie_t *value);

/*
 * @brief  : decodes gtpv1 trigger ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_trigger_id_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_trigger_id_ie(const uint8_t *buf, gtpv1_trigger_id_ie_t *value);

/*
 * @brief  : decodes gtpv1 omc identity IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_omc_identity_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_omc_identity_ie(const uint8_t *buf, gtpv1_omc_identity_ie_t *value);

/*
 * @brief  : decodes gtpv1 user location info IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_user_location_information_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_user_location_information_ie(const uint8_t *buf, gtpv1_user_location_information_ie_t *value);

/*
 * @brief  : decodes gtpv1 ms time zone IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ms_time_zone_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ms_time_zone_ie(const uint8_t *buf, gtpv1_ms_time_zone_ie_t *value);

/*
 * @brief  : decodes gtpv1 camel charging info container IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_camel_charging_information_container_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_camel_charging_information_container_ie(const uint8_t *buf, gtpv1_camel_charging_information_container_ie_t *value);

/*
 * @brief  : decodes gtpv1 additional trace info IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_additional_trace_information_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_additional_trace_information_ie(const uint8_t *buf, gtpv1_additional_trace_information_ie_t *value);

/*
 * @brief  : decodes gtpv1 correlation ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_correlation_id_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_correlation_id_ie(const uint8_t *buf, gtpv1_correlation_id_ie_t *value);

/*
 * @brief  : decodes gtpv1 user csg info IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_user_csg_information_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_user_csg_information_ie(const uint8_t *buf, gtpv1_user_csg_information_ie_t *value);

/*
 * @brief  : decodes gtpv1 signalling priority indication ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_signalling_priority_indication_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_signalling_priority_indication_ie(const uint8_t *buf, gtpv1_signalling_priority_indication_ie_t *value);

/*
 * @brief  : decodes gtpv1 cn operator selection entity IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_cn_operator_selection_entity_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_cn_operator_selection_entity_ie(const uint8_t *buf, gtpv1_cn_operator_selection_entity_ie_t *value);

/*
 * @brief  : decodes gtpv1 mapped ue usage type IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_mapped_ue_usage_type_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_mapped_ue_usage_type_ie(const uint8_t *buf, gtpv1_mapped_ue_usage_type_ie_t *value);

/*
 * @brief  : decodes gtpv1 up function selction indication IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_up_function_selection_indication_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_up_function_selection_indication_ie(const uint8_t *buf, gtpv1_up_function_selection_indication_ie_t *value);

/*
 * @brief  : decodes gtpv1 teardown indication IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_teardown_ind_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_teardown_ind_ie(const uint8_t *buf, gtpv1_teardown_ind_ie_t *value);

/*
 * @brief  : decodes gtpv1 uli time stamp IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_uli_timestamp_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_uli_timestamp_ie(const uint8_t *buf, gtpv1_uli_timestamp_ie_t *value);

/*
 * @brief  : decodes gtpv1 direct tunnel flag IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_direct_tunnel_flag_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_direct_tunnel_flag_ie(const uint8_t *buf, gtpv1_direct_tunnel_flag_ie_t *value);

/*
 * @brief  : decodes gtpv1 map cause IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_map_casue_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_map_cause_ie(const uint8_t *buf, gtpv1_map_cause_ie_t *value);

/*
 * @brief  : decodes gtpv1 ms not reachable reason IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ms_not_rechable_reason_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ms_not_rechable_reason_ie(const uint8_t *buf, gtpv1_ms_not_rechable_reason_ie_t *value);

/*
 * @brief  : decodes gtpv1 temporary logical link identifier IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_temporary_logical_link_identifier_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_temporary_logical_link_identifier_ie(const uint8_t *buf, gtpv1_temporary_logical_link_identifier_ie_t *value);

/*
 * @brief  : decodes gtpv1 packet tmsi IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_packet_tmsi_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_packet_tmsi_ie(const uint8_t *buf, gtpv1_packet_tmsi_ie_t *value);

/*
 * @brief  : decodes gtpv1 p tmsi signature IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_p_tmsi_signature_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_p_tmsi_signature_ie(const uint8_t *buf, gtpv1_p_tmsi_signature_ie_t *value);

/*
 * @brief  : decodes gtpv1 ms validate IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ms_validated_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ms_validated_ie(const uint8_t *buf, gtpv1_ms_validated_ie_t *value);

/*
 * @brief  : decodes gtpv1 sgsn number IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_sgsn_number_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_sgsn_number_ie(const uint8_t *buf, gtpv1_sgsn_number_ie_t *value);

/*
 * @brief  : decodes gtpv1 hop counter IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_hop_counter_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_hop_counter_ie(const uint8_t *buf, gtpv1_hop_counter_ie_t *value);

/*
 * @brief  : decodes gtpv1 rab context IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_rab_context_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_rab_context_ie(const uint8_t *buf, gtpv1_rab_context_ie_t *value);

/*
 * @brief  : decodes gtpv1 radio priority sms IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_radio_priority_sms_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_radio_priority_sms_ie(const uint8_t *buf, gtpv1_radio_priority_sms_ie_t *value);

/*
 * @brief  : decodes gtpv1 radio priority IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_radio_priority_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_radio_priority_ie(const uint8_t *buf, gtpv1_radio_priority_ie_t *value);

/*
 * @brief  : decodes gtpv1 packet flow ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_packet_flow_id_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_packet_flow_id_ie(const uint8_t *buf, gtpv1_packet_flow_id_ie_t *value);

/*
 * @brief  : decodes gtpv1 radio priority lcs IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_radio_priority_lcs_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_radio_priority_lcs_ie(const uint8_t *buf, gtpv1_radio_priority_lcs_ie_t *value);

/*
 * @brief  : decodes gtpv1 used cipher value umts keys and quintuplets IE from buffer
 * @param  : buf, buffer to decode
 * @param  : value, gtpv1_used_cipher_value_umts_keys_and_quintuplets_t structure which will store decoded values
 * @param  : total_decoded, total bits already decoded
 * @return : success 'number of decoded bits'
 */
int16_t decode_gtpv1_used_cipher_value_umts_keys_and_quintuplets(const uint8_t *buf, 
		gtpv1_used_cipher_value_umts_keys_and_quintuplets_t *value, uint16_t total_decoded);

/*
 * @brief  : decodes gtpv1 gsm key and triplet IE from buffer
 * @param  : buf, buffer to decode
 * @param  : value, gtpv1_gsm_key_and_triplet_t structure which will store decoded values
 * @param  : total_decoded, total bits already decoded
 * @return : success 'number of decoded bits'
 */
int16_t decode_gtpv1_gsm_keys_and_triplet(const uint8_t *buf, gtpv1_gsm_key_and_triplet_t *value, uint16_t total_decoded);

/*
 * @brief  : decodes gtpv1 umts keys and quintuplets IE from buffer
 * @param  : buf, buffer to decode
 * @param  : value, gtpv1_umts_keys_and_quintuplets_t structure which will store decoded values
 * @param  : total_decoded, total bits already decoded
 * @return : success 'number of decoded bits'
 */
int16_t decode_gtpv1_umts_keys_and_quintuplets(const uint8_t *buf, gtpv1_umts_keys_and_quintuplets_t *value,
		uint16_t total_decoded);

/*
 * @brief  : decodes gtpv1 gsm keys and umts quintuplets IE from buffer
 * @param  : buf, buffer to decode
 * @param  : value, gtpv1_gsm_keys_and_umts_quintuplets_t structure which will store decoded values
 * @param  : total_decoded, total bits already decoded
 * @return : success 'number of decoded bits'
 */
int16_t decode_gtpv1_gsm_keys_and_umts_quintuplets(const uint8_t *buf, gtpv1_gsm_keys_and_umts_quintuplets_t *value,
		uint16_t total_decoded);

/*
 * @brief  : decodes gtpv1 ms network capability value IE from buffer
 * @param  : buf, buffer to decode
 * @param  : value, gtpv1_ms_network_capability_value_t structure which will store decoded values
 * @param  : total_decoded, total bits already decoded
 * @return : success 'number of decoded bits'
 */
int16_t decode_ms_network_capability_value(const uint8_t *buf, gtpv1_ms_network_capability_value_t *value, 
		uint16_t total_decoded);
/*
 * @brief  : decodes gtpv1 mm context IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_mm_context_ie_t_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_mm_context_ie(const uint8_t *buf, gtpv1_mm_context_ie_t *value);

/*
 * @brief  : decodes gtpv1 pdp context IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdp_context_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_pdp_context_ie(const uint8_t *buf, gtpv1_pdp_context_ie_t *value);

/*
 * @brief  : decodes gtpv1 pdp context prioritization IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdp_context_prioritization_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_pdp_context_prioritization_ie(const uint8_t *buf, gtpv1_pdp_context_prioritization_ie_t *value);

/*
 * @brief  : decodes gtpv1 mbms ue context IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_mbms_ue_context_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_mbms_ue_context_ie(const uint8_t *buf, gtpv1_mbms_ue_context_ie_t *value);

/*
 * @brief  : decodes gtpv1 rfsp index IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_rfsp_index_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_rfsp_index_ie(const uint8_t *buf, gtpv1_rfsp_index_ie_t *value);

/*
 * @brief  : decodes gtpv1 fqdn IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_fqdn_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_fqdn_ie(const uint8_t *buf, gtpv1_fqdn_ie_t *value);

/*
 * @brief  : decodes gtpv1 evolved allocation retention priority II IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_evolved_allocation_retention_priority_II_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_evolved_allocation_retention_priority_II_ie(
		const uint8_t *buf, gtpv1_evolved_allocation_retention_priority_II_ie_t *value);

/*
 * @brief  : decodes gtpv1 ue network capability IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ue_network_capability_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ue_network_capability_ie(const uint8_t *buf, gtpv1_ue_network_capability_ie_t *value);

/*
 * @brief  : decodes gtpv1 ue ambr IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ue_ambr_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ue_ambr_ie(const uint8_t *buf, gtpv1_ue_ambr_ie_t *value);

/*
 * @brief  : decodes gtpv1 apn ambr with nsapi IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_apn_ambr_with_nsapi_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_apn_ambr_with_nsapi_ie(const uint8_t *buf, gtpv1_apn_ambr_with_nsapi_ie_t *value);

/*
 * @brief  : decodes gtpv1 signalling priority indication with nsapi IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_signalling_priority_indication_with_nsapi_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_signalling_priority_indication_with_nsapi_ie(
		const uint8_t *buf, gtpv1_signalling_priority_indication_with_nsapi_ie_t *value);

/*
 * @brief  : decodes gtpv1 higher bitrates than 16 mbps flag IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_higher_bitrates_than_16_mbps_flag_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(const uint8_t *buf, gtpv1_higher_bitrates_than_16_mbps_flag_ie_t *value);

/*
 * @brief  : decodes gtpv1 selection mode with nsapi IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_selection_mode_with_nsapi_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_selection_mode_with_nsapi_ie(const uint8_t *buf, gtpv1_selection_mode_with_nsapi_ie_t *value);

/*
 * @brief  : decodes gtpv1 local home network id with nsapi IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_local_home_network_id_with_nsapi_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_local_home_network_id_with_nsapi_ie(const uint8_t *buf, gtpv1_local_home_network_id_with_nsapi_ie_t *value);

/*
 * @brief  : decodes gtpv1 ue usage type IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ue_usage_type_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ue_usage_type_ie(const uint8_t *buf, gtpv1_ue_usage_type_ie_t *value);

/*
 * @brief  : decodes gtpv1 ue scef pdn connection IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ue_scef_pdn_connection_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ue_scef_pdn_connection_ie(const uint8_t *buf, gtpv1_ue_scef_pdn_connection_ie_t *value);

/*
 * @brief  : decodes gtpv1 iov updates counter IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_iov_updates_counter_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_iov_updates_counter_ie(const uint8_t *buf, gtpv1_iov_updates_counter_ie_t *value);

/*
 * @brief  : decodes gtpv1 ran transparent container IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ran_transparent_container_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ran_transparent_container_ie(const uint8_t *buf, gtpv1_ran_transparent_container_ie_t *value);

/*
 * @brief  : decodes gtpv1 rim routing address IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_rim_routing_addr_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_rim_routing_addr_ie(const uint8_t *buf, gtpv1_rim_routing_addr_ie_t *value);

/*
 * @brief  : decodes gtpv1 rim routing address disc IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_rim_routing_addr_disc_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_rim_routing_addr_disc_ie(const uint8_t *buf, gtpv1_rim_routing_addr_disc_ie_t *value);

/*
 * @brief  : decodes gtpv1 selected plmn ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_selected_plmn_id_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_selected_plmn_id_ie(const uint8_t *buf, gtpv1_selected_plmn_id_ie_t *value);

/*
 * @brief  : decodes gtpv1 mbms protocol config option from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_mbms_protocol_config_options_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_mbms_protocol_config_options_ie(const uint8_t *buf, gtpv1_mbms_protocol_config_options_ie_t *value);

/*
 * @brief  : decodes gtpv1 teid data 2 IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_teid_2_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_teid_data_2_ie(const uint8_t *buf, gtpv1_teid_data_2_ie_t *value);

/*
 * @brief  : decodes gtpv1 ranap cause IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ranap_cause_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ranap_cause_ie(const uint8_t *buf, gtpv1_ranap_cause_ie_t *value);

/*
 * @brief  : decodes gtpv1 traget identification IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_target_identification_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_target_identification_ie(const uint8_t *buf, gtpv1_target_identification_ie_t *value);

/*
 * @brief  : decodes gtpv1 utran transparent container IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_utran_transparent_container_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_utran_transparent_container_ie(const uint8_t *buf, gtpv1_utran_transparent_container_ie_t *value);

/*
 * @brief  : decodes gtpv1 rab setup info IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_rab_setup_info_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_rab_setup_info_ie(const uint8_t *buf, gtpv1_rab_setup_info_ie_t *value);

/*
 * @brief  : decodes gtpv1 bss container IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_bss_conatiner_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_bss_container_ie(const uint8_t *buf, gtpv1_bss_container_ie_t *value);

/*
 * @brief  : decodes gtpv1 cell identification IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_cell_identification_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_cell_identification_ie(const uint8_t *buf, gtpv1_cell_identification_ie_t *value);

/*
 * @brief  : decodes gtpv1 bssgp cause IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_bssgp_causee_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_bssgp_cause_ie(const uint8_t *buf, gtpv1_bssgp_cause_ie_t *value);

/*
 * @brief  : decodes gtpv1 list of setup pfcs IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_list_of_setup_pfcs_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_list_of_setup_pfcs_ie(const uint8_t *buf, gtpv1_list_of_setup_pfcs_ie_t *value);

/*
 * @brief  : decodes gtpv1 ps handover xid param IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_ps_handover_xid_param_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_ps_handover_xid_param_ie(const uint8_t *buf, gtpv1_ps_handover_xid_param_ie_t *value);

/*
 * @brief  : decodes gtpv1 reliable inter rat handover info from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_reliable_inter_rat_handover_info_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_reliable_inter_rat_handover_info_ie(const uint8_t *buf, gtpv1_reliable_inter_rat_handover_info_ie_t *value);

/*
 * @brief  : decodes gtpv1 csg ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_csg_id_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_csg_id_ie(const uint8_t *buf, gtpv1_csg_id_ie_t *value);

/*
 * @brief  : decodes gtpv1 csg membership indication IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_csg_membership_indication_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_csg_membership_indication_ie(const uint8_t *buf, gtpv1_csg_membership_indication_ie_t *value);

/*
 * @brief  : decodes gtpv1 additional mm context for service IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_additional_mm_ctxt_for_srvcc_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(const uint8_t *buf, gtpv1_additional_mm_ctxt_for_srvcc_ie_t *value);

/*
 * @brief  : decodes gtpv1 additional flags for srvcc IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_additional_flags_for_srvcc_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_additional_flags_for_srvcc_ie(const uint8_t *buf, gtpv1_additional_flags_for_srvcc_ie_t *value);

/*
 * @brief  : decodes gtpv1 stn sr IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_stn_sr_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_stn_sr_ie(const uint8_t *buf, gtpv1_stn_sr_ie_t *value);

/*
 * @brief  : decodes gtpv1 c msisdn from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_c_msisdn_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_c_msisdn_ie(const uint8_t *buf, gtpv1_c_msisdn_ie_t *value);

/*
 * @brief  : decodes gtpv1 extended ranap cause IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_extended_ranap_cause_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_extended_ranap_cause_ie(const uint8_t *buf, gtpv1_extended_ranap_cause_ie_t *value);

/*
 * @brief  : decodes gtpv1 enodeb ID IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_enodeb_id_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_enodeb_id_ie(const uint8_t *buf, gtpv1_enodeb_id_ie_t *value);

/*
 * @brief  : decodes gtpv1 node identifier IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_node_identifier_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_node_identifier_ie(const uint8_t *buf, gtpv1_node_identifier_ie_t *value);

/*
 * @brief  : decodes gtpv1 auth triplet value from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_auth_triplet_value_t structure which will store decoded values
 * @return : 'number of decoded bits'
 */
int16_t decode_auth_triplet_value(const uint8_t *buf, gtpv1_auth_triplet_value_t *value, uint16_t total_decoded);

/*
 * @brief  : decodes gtpv1 auth triplet IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_auth_triplet_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_auth_triplet_ie(const uint8_t *buf, gtpv1_auth_triplet_ie_t *value);

/*
 * @brief  : decodes gtpv1 auth quintuplet value from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_auth_quintuplet_value_t structure which will store decoded values
 * @return : 'number of decoded bits'
 */
int16_t decode_auth_quintuplet_value(const uint8_t *buf, gtpv1_auth_quintuplet_value_t *value, uint16_t total_decoded);

/*
 * @brief  : decodes gtpv1 auth quintuplet IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_auth_quintuplet_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_auth_quintuplet_ie(const uint8_t *buf, gtpv1_auth_quintuplet_ie_t *value);

/*
 * @brief  : decodes gtpv1 source rnc pdcp context info IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_src_rnc_pdcp_ctxt_info_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(const uint8_t *buf, gtpv1_src_rnc_pdcp_ctxt_info_ie_t *value);

/*
 * @brief  : decodes gtpv1 pdu numbers IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_pdu_numbers_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_pdu_numbers_ie(const uint8_t *buf, gtpv1_pdu_numbers_ie_t *value);

/*
 * @brief  : decodes gtpv1 extension header type IE from buffer.
 * @param  : buf, buffer to decode.
 * @param  : value, gtpv1_extension_header_type_list_ie_t structure which will store decoded values
 * @return : success 'number of decoded bytes', failure '-1'.
 */
int16_t decode_gtpv1_extension_header_type_list_ie(const uint8_t *buf, gtpv1_extension_header_type_list_ie_t *value);

#ifdef __cplusplus
}
#endif

#endif /*__GTPV1_IES_DECODER_H__*/
