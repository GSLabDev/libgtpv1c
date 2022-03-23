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

#ifndef __TEST_DECODER_GTPV1_IES_H__
#define __TEST_DECODER_GTPV1_IES_H__

#ifdef __cplusplus
	extern "C" {
#endif

#include <assert.h>
#include "CUnit/Basic.h"
#include "../include/enc_dec_bits.h"
#include "../include/gtpv1_ies.h"
#include "../include/gtpv1_ies_decoder.h"

/*
 * @brief  : unit test cases of decoding of gtpv1 header
 * @return : null
 */
void test_decode_gtpv1_header(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 cause ie
 * @return : null
 */
void test_decode_gtpv1_cause_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 imsi ie
 * @return : null
 */
void test_decode_gtpv1_imsi_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 routing_area_identity ie
 * @return : null
 */
void test_decode_gtpv1_routing_area_identity_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 reordering_req ie
 * @return : null
 */
void test_decode_gtpv1_reordering_req_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 recovery ie
 * @return : null
 */
void test_decode_gtpv1_recovery_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 selection_mode ie
 * @return : null
 */
void test_decode_gtpv1_selection_mode_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 teid data 1 ie
 * @return : null
 */
void test_decode_gtpv1_teid_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 teardown ind ie
 * @return : null
 */
void test_decode_gtpv1_teardown_ind_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 nsapi ie
 * @return : null
 */
void test_decode_gtpv1_nsapi_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 charging char ie
 * @return : null
 */
void test_decode_gtpv1_chrgng_char_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 trace reference ie
 * @return : null
 */
void test_decode_gtpv1_trace_reference_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 trace type ie
 * @return : null
 */
void test_decode_gtpv1_trace_type_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 charging id ie
 * @return : null
 */
void test_decode_gtpv1_charging_id_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 end user address ie
 * @return : null
 */
void test_decode_gtpv1_end_user_address_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 apn ie
 * @return : null
 */
void test_decode_gtpv1_apn_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 protocol config options ie
 * @return : null
 */
void test_decode_gtpv1_protocol_config_options_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 gsn address ie
 * @return : null
 */
void test_decode_gtpv1_gsn_addr_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 msisdn ie
 * @return : null
 */
void test_decode_gtpv1_msisdn_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 qos ie
 * @return : null
 */
void test_decode_gtpv1_qos_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 traffic flow template ie
 * @return : null
 */
void test_decode_gtpv1_traffic_flow_tmpl_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 trigger id ie
 * @return : null
 */
void test_decode_gtpv1_trigger_id_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 omc identity ie
 * @return : null
 */
void test_decode_gtpv1_omc_identity_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 common flag ie
 * @return : null
 */
void test_decode_gtpv1_common_flag_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 apn restriction ie
 * @return : null
 */
void test_decode_gtpv1_apn_restriction_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 rat type ie
 * @return : null
 */
void test_decode_gtpv1_rat_type_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 user location information ie
 * @return : null
 */
void test_decode_gtpv1_user_location_information_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ms time zone ie
 * @return : null
 */
void test_decode_gtpv1_ms_time_zone_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 imei ie
 * @return : null
 */
void test_decode_gtpv1_imei_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 camel charging information container ie
 * @return : null
 */
void test_decode_gtpv1_camel_charging_information_container_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 additional trace information ie
 * @return : null
 */
void test_decode_gtpv1_additional_trace_information_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ms info change reporting action ie
 * @return : null
 */
void test_decode_gtpv1_ms_info_change_reporting_action_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 direct tunnel flag ie
 * @return : null
 */
void test_decode_gtpv1_direct_tunnel_flag_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 correlation id ie
 * @return : null
 */
void test_decode_gtpv1_correlation_id_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 bearer control mode ie
 * @return : null
 */
void test_decode_gtpv1_bearer_control_mode_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 evolved allocation retention priority 1 ie
 * @return : null
 */
void test_decode_gtpv1_evolved_allocation_retention_priority_1_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 extended common flag ie
 * @return : null
 */
void test_decode_gtpv1_extended_common_flag_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 user csg information ie
 * @return : null
 */
void test_decode_gtpv1_user_csg_information_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 csg information reporting action ie
 * @return : null
 */
void test_decode_gtpv1_csg_information_reporting_action_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 apn ambr ie
 * @return : null
 */
void test_decode_gtpv1_apn_ambr_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ggsn back off time ie
 * @return : null
 */
void test_decode_gtpv1_ggsn_back_off_time_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 signalling priority indication ie
 * @return : null
 */
void test_decode_gtpv1_signalling_priority_indication_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 uli timestamp ie
 * @return : null
 */
void test_decode_gtpv1_uli_timestamp_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 cn operator selection entity ie
 * @return : null
 */
void test_decode_gtpv1_cn_operator_selection_entity_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 extended common flag 2 ie
 * @return : null
 */
void test_decode_gtpv1_extended_common_flags_2_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 mapped ue usage type ie
 * @return : null
 */
void test_decode_gtpv1_mapped_ue_usage_type_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 up function selection indication ie
 * @return : null
 */
void test_decode_gtpv1_up_function_selection_indication_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 charging gateway addr ie
 * @return : null
 */
void test_decode_gtpv1_charging_gateway_addr_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 private extension ie
 * @return : null
 */
void test_decode_gtpv1_private_extension_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 map cause ie
 * @return : null
 */
void test_decode_gtpv1_map_cause_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ms not rechable reason ie
 * @return : null
 */
void test_decode_gtpv1_ms_not_rechable_reason_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 temporary logical link identifier ie
 * @return : null
 */
void test_decode_gtpv1_temporary_logical_link_identifier_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 packet tmsi ie
 * @return : null
 */
void test_decode_gtpv1_packet_tmsi_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 p tmsi signature ie
 * @return : null
 */
void test_decode_gtpv1_p_tmsi_signature_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ms validated ie
 * @return : null
 */
void test_decode_gtpv1_ms_validated_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 sgsn number ie
 * @return : null
 */
void test_decode_gtpv1_sgsn_number_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 hop counter ie
 * @return : null
 */
void test_decode_gtpv1_hop_counter_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 rab context ie
 * @return : null
 */
void test_decode_gtpv1_rab_context_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 radio priority sms ie
 * @return : null
 */
void test_decode_gtpv1_radio_priority_sms_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 radio priority ie
 * @return : null
 */
void test_decode_gtpv1_radio_priority_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 packet flow id ie
 * @return : null
 */
void test_decode_gtpv1_packet_flow_id_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 radio priority lcs ie
 * @return : null
 */
void test_decode_gtpv1_radio_priority_lcs_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 pdp context prioritization ie
 * @return : null
 */
void test_decode_gtpv1_pdp_context_prioritization_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 rfsp index ie
 * @return : null
 */
void test_decode_gtpv1_rfsp_index_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 fqdn ie
 * @return : null
 */
void test_decode_gtpv1_fqdn_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 evolved allocation retention priority II ie
 * @return : null
 */
void test_decode_gtpv1_evolved_allocation_retention_priority_II_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ue network capability ie
 * @return : null
 */
void test_decode_gtpv1_ue_network_capability_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 apn ambr with nsapi ie
 * @return : null
 */
void test_decode_gtpv1_apn_ambr_with_nsapi_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 signalling priority indication with nsapi ie
 * @return : null
 */
void test_decode_gtpv1_signalling_priority_indication_with_nsapi_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 higher bitrates than 16 mbps flag ie
 * @return : null
 */
void test_decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 selection mode with nsapi ie
 * @return : null
 */
void test_decode_gtpv1_selection_mode_with_nsapi_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 local home network id with nsapi ie
 * @return : null
 */
void test_decode_gtpv1_local_home_network_id_with_nsapi_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ran transparent container ie
 * @return : null
 */
void test_decode_gtpv1_ran_transparent_container_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 rim routing addr ie
 * @return : null
 */
void test_decode_gtpv1_rim_routing_addr_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 rim routing addr discriminator ie
 * @return : null
 */
void test_decode_gtpv1_rim_routing_addr_disc_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 selected plmn id ie
 * @return : null
 */
void test_decode_gtpv1_selected_plmn_id_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 mbms protocol config options ie
 * @return : null
 */
void test_decode_gtpv1_mbms_protocol_config_options_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 teid data 2 ie
 * @return : null
 */
void test_decode_gtpv1_teid_data_2_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ranap cause ie
 * @return : null
 */
void test_decode_gtpv1_ranap_cause_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 target identification ie
 * @return : null
 */
void test_decode_gtpv1_target_identification_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 utran transparent container ie
 * @return : null
 */
void test_decode_gtpv1_utran_transparent_container_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 rab setup info ie
 * @return : null
 */
void test_decode_gtpv1_rab_setup_info_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 bss container ie
 * @return : null
 */
void test_decode_gtpv1_bss_container_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 cell identification ie
 * @return : null
 */
void test_decode_gtpv1_cell_identification_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 bssgp cause ie
 * @return : null
 */
void test_decode_gtpv1_bssgp_cause_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 list of setup pfcs ie
 * @return : null
 */
void test_decode_gtpv1_list_of_setup_pfcs_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ps handover xid param ie
 * @return : null
 */
void test_decode_gtpv1_ps_handover_xid_param_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 reliable inter rat handover info ie
 * @return : null
 */
void test_decode_gtpv1_reliable_inter_rat_handover_info_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 csg id ie
 * @return : null
 */
void test_decode_gtpv1_csg_id_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 csg membership indication ie
 * @return : null
 */
void test_decode_gtpv1_csg_membership_indication_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 additional mm ctxt for srvcc ie
 * @return : null
 */
void test_decode_gtpv1_additional_mm_ctxt_for_srvcc_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 additional flags for srvcc ie
 * @return : null
 */
void test_decode_gtpv1_additional_flags_for_srvcc_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 stn sr ie
 * @return : null
 */
void test_decode_gtpv1_stn_sr_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 c msisdn ie
 * @return : null
 */
void test_decode_gtpv1_c_msisdn_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 extended ranap cause ie
 * @return : null
 */
void test_decode_gtpv1_extended_ranap_cause_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 enodeb id ie
 * @return : null
 */
void test_decode_gtpv1_enodeb_id_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 node identifier ie
 * @return : null
 */
void test_decode_gtpv1_node_identifier_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 mm context ie
 * @return : null
 */
void test_decode_gtpv1_mm_context_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 pdp context ie
 * @return : null
 */
void test_decode_gtpv1_pdp_context_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 mbms ue context ie
 * @return : null
 */
void test_decode_gtpv1_mbms_ue_context_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ue ambr ie
 * @return : null
 */
void test_decode_gtpv1_ue_ambr_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ue scef pdn connection ie
 * @return : null
 */
void test_decode_gtpv1_ue_scef_pdn_connection_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 auth triplet ie
 * @return : null
 */
void test_decode_gtpv1_auth_triplet_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 auth quintuplet ie
 * @return : null
 */
void test_decode_gtpv1_auth_quintuplet_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 src rnc pdcp ctxt info ie
 * @return : null
 */
void test_decode_gtpv1_src_rnc_pdcp_ctxt_info_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 pdu numbers ie
 * @return : null
 */
void test_decode_gtpv1_pdu_numbers_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 extension header type list ie
 * @return : null
 */
void test_decode_gtpv1_extension_header_type_list_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 iov updates counter ie
 * @return : null
 */
void test_decode_gtpv1_iov_updates_counter_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 ue usage type ie
 * @return : null
 */
void test_decode_gtpv1_ue_usage_type_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 teid control plane ie
 * @return : null
 */
void test_decode_gtpv1_teid_control_plane_ie(void);

/*
 * @brief  : unit test cases of decoding of gtpv1 additional rab setup information ie
 * @return : null
 */
void test_decode_gtpv1_additional_rab_setup_info_ie(void);

#ifdef __cplusplus
}
#endif

#endif /*__TEST_DECODER_GTPV1_IES_H__*/
