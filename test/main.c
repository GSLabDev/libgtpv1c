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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "CUnit/Automated.h"
#include "CUnit/Basic.h"
#include "test_encoder_gtpv1_ies.h"
#include "test_decoder_gtpv1_ies.h"
#include "test_encoder_gtpv1_messages.h"
#include "test_decoder_gtpv1_messages.h"

int init_suite(void)
{
	return 0;
}

int clean_suite(void)
{
	return 0;
}

int main()
{
	CU_pSuite eSuite = NULL;
	CU_pSuite dSuite = NULL;
	CU_pSuite meSuite = NULL;
	CU_pSuite mdSuite = NULL;

	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	eSuite = CU_add_suite("ENCODING Suite", init_suite, clean_suite);
	dSuite = CU_add_suite("DECODING Suite", init_suite, clean_suite);
	meSuite = CU_add_suite("ENCODING MESSAGE Suite", init_suite, clean_suite);	
	mdSuite = CU_add_suite("DECODING MESSAGE Suite", init_suite, clean_suite);

	if (NULL == eSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == dSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == meSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (NULL == mdSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (	(NULL == CU_add_test(eSuite, "test of gtpv1 header()",
								test_encode_gtpv1_header))     ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 cause_ie()", 
								test_encode_gtpv1_cause_ie)) 		||
		(NULL == CU_add_test(eSuite, "test of gtpv1 imsi_ie()", 
								test_encode_gtpv1_imsi_ie))		|| 
		(NULL == CU_add_test(eSuite, "test of gtpv1 routing_area_identity_ie()", 
								test_encode_gtpv1_routing_area_identity_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 reordering_req_ie()", 
								test_encode_gtpv1_reordering_req_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 recovery_ie()", 
								test_encode_gtpv1_recovery_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 selection_mode_ie()", 
								test_encode_gtpv1_selection_mode_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 teid_ie()", 
								test_encode_gtpv1_teid_ie))||
		(NULL == CU_add_test(eSuite, "test of gtpv1 teardown_ind_ie()", 
								test_encode_gtpv1_teardown_ind_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 nsapi_ie()", 	test_encode_gtpv1_nsapi_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 chrgng_char_ie()", 
								test_encode_gtpv1_chrgng_char_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 trace_reference_ie()", 
								test_encode_gtpv1_trace_reference_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 trace_type_ie()", 
								test_encode_gtpv1_trace_type_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 charging_id_ie()", 
								test_encode_gtpv1_charging_id_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 end_user_addr_ie()", 
								test_encode_gtpv1_end_user_address_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 apn_ie()", 
								test_encode_gtpv1_apn_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 protocol_config_options_ie()",
								test_encode_gtpv1_protocol_config_options_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 gsn_addr_ie()", test_encode_gtpv1_gsn_addr_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 msisdn_ie()", test_encode_gtpv1_msisdn_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 qos_ie()", test_encode_gtpv1_qos_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 traffic_flow_tmpl_ie()",
								test_encode_gtpv1_traffic_flow_tmpl_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 trigger_id_ie()", 
								test_encode_gtpv1_trigger_id_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 omc_identity_ie()", 
								test_encode_gtpv1_omc_identity_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 common_flag_ie()", 
								test_encode_gtpv1_common_flag_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 apn_restriction_ie()", 
								test_encode_gtpv1_apn_restriction_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 rat_type_ie()",
								test_encode_gtpv1_rat_type_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 user_location_information_ie()",
								test_encode_gtpv1_user_location_information_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ms_time_zone_ie()",
								test_encode_gtpv1_ms_time_zone_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 imei_ie()",
								test_encode_gtpv1_imei_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 camel_charging_information_container_ie",
								test_encode_gtpv1_camel_charging_information_container_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 additional_trace_information_ie()",
								test_encode_gtpv1_additional_trace_information_ie))	||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ms_info_change_reporting_action_ie()",
								test_encode_gtpv1_ms_info_change_reporting_action_ie))     ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 direct_tunnel_flag_ie()",
								test_encode_gtpv1_direct_tunnel_flag_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 correlation_id_ie()",
								test_encode_gtpv1_correlation_id_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 bearer_control_mode_ie()",
								test_encode_gtpv1_bearer_control_mode_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 evolved_allocation_retention_priority_1_ie()",
								test_encode_gtpv1_evolved_allocation_retention_priority_1_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 extended_common_flag_ie()",
								test_encode_gtpv1_extended_common_flag_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 user_csg_information_ie()",
								test_encode_gtpv1_user_csg_information_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 csg_information_reporting_action_ie()",
								test_encode_gtpv1_csg_information_reporting_action_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 apn_ambr_ie()",
								test_encode_gtpv1_apn_ambr_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ggsn_back_off_time_ie()",
								test_encode_gtpv1_ggsn_back_off_time_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 signalling_priority_indication_ie()",
								test_encode_gtpv1_signalling_priority_indication_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 uli_timestamp_ie()",
								test_encode_gtpv1_uli_timestamp_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 cn_operator_selection_entity_ie()",
								test_encode_gtpv1_cn_operator_selection_entity_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 extended_common_flags_2_ie()",
								test_encode_gtpv1_extended_common_flag_2_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 mapped_ue_usage_type_ie()",
								test_encode_gtpv1_mapped_ue_usage_type_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 up_function_selection_indication_ie()",
								test_encode_gtpv1_up_function_selection_indication_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 charging_gateway_addr_ie()",
								test_encode_gtpv1_charging_gateway_addr_ie))    ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 private_extension_ie()",
								test_encode_gtpv1_private_extension_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 map_cause_ie()",
								test_encode_gtpv1_map_cause_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ms_not_rechable_reason_ie()",
								test_encode_gtpv1_ms_not_rechable_reason_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 temporary_logical_link_identifie_ie()",
								test_encode_gtpv1_temporary_logical_link_identifier_ie))||
		(NULL == CU_add_test(eSuite, "test of gtpv1 packet_tmsi_ie()",
								test_encode_gtpv1_packet_tmsi_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 p_tmsi_signature_ie()",
								test_encode_gtpv1_p_tmsi_signature_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ms_validated_ie()",
								test_encode_gtpv1_ms_validated_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 sgsn_number_ie()",
								test_encode_gtpv1_sgsn_number_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 hop_counter_ie()",
								test_encode_gtpv1_hop_counter_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 rab_context_ie()",
								test_encode_gtpv1_rab_context_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 radio_priority_sms_ie()",
								test_encode_gtpv1_radio_priority_sms_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 radio_priority_ie()",
								test_encode_gtpv1_radio_priority_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 packet_flow_id_ie()",
								test_encode_gtpv1_packet_flow_id_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 radio_priority_lcs_ie()",
								test_encode_gtpv1_radio_priority_lcs_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 pdp_context_prioritization_ie()",
								test_encode_gtpv1_pdp_context_prioritization_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 rfsp_index_ie()",
								test_encode_gtpv1_rfsp_index_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 fqdn_ie()",
								test_encode_gtpv1_fqdn_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 evolved_allocation_retention_priority_II_ie()",
								test_encode_gtpv1_evolved_allocation_retention_priority_II_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ue_network_capability_ie()",
								test_encode_gtpv1_ue_network_capability_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 apn_ambr_with_nsapi_ie()",
								test_encode_gtpv1_apn_ambr_with_nsapi_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 signalling_priority_indication_with_nsapi_ie()",
								test_encode_gtpv1_signalling_priority_indication_with_nsapi_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 higher_bitrates_than_16_mbps_flag_ie()",
								test_encode_gtpv1_higher_bitrates_than_16_mbps_flag_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 selection_mode_with_nsapi_ie()",
								test_encode_gtpv1_selection_mode_with_nsapi_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 local_home_network_id_with_nsapi_ie()",
								test_encode_gtpv1_local_home_network_id_with_nsapi_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ran_transparent_container_ie()",
								test_encode_gtpv1_ran_transparent_container_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 rim_routing_addr_ie()",
								test_encode_gtpv1_rim_routing_addr_ie))||
		(NULL == CU_add_test(eSuite, "test of gtpv1 rim_routing_addr_disc_ie()",
								test_encode_gtpv1_rim_routing_addr_disc_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 selected_plmn_id_ie()",
								test_encode_gtpv1_selected_plmn_id_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 mbms_protocol_config_options_ie()",
								test_encode_gtpv1_mbms_protocol_config_options_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 teid_data_2_ie()",
								test_encode_gtpv1_teid_data_2_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ranap_cause_ie()",
								test_encode_gtpv1_ranap_cause_ie))||
		(NULL == CU_add_test(eSuite, "test of gtpv1 target_identification_ie()",
								test_encode_gtpv1_target_identification_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 utran_transparent_container_ie()",
								test_encode_gtpv1_utran_transparent_container_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 rab_setup_info_ie()",
								test_encode_gtpv1_rab_setup_info_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 bss_container_ie()",
								test_encode_gtpv1_bss_container_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 cell_identification_ie()",
								test_encode_gtpv1_cell_identification_ie))||
		(NULL == CU_add_test(eSuite, "test of gtpv1 bssgp_cause_ie()",
								test_encode_gtpv1_bssgp_cause_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 list_of_setup_pfcs_ie()",
								test_encode_gtpv1_list_of_setup_pfcs_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ps_handover_xid_param_ie()",
								test_encode_gtpv1_ps_handover_xid_param_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 reliable_inter_rat_handover_info_ie()",
								test_encode_gtpv1_reliable_inter_rat_handover_info_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 csg_id_ie()",
								test_encode_gtpv1_csg_id_ie))||
		(NULL == CU_add_test(eSuite, "test of gtpv1 csg_membership_indication_ie()",
								test_encode_gtpv1_csg_membership_indication_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 additional_mm_ctxt_for_srvcc_ie()",
								test_encode_gtpv1_additional_mm_ctxt_for_srvcc_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 additional_flags_for_srvcc_ie()",
								test_encode_gtpv1_additional_flags_for_srvcc_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 stn_sr_ie()",
								test_encode_gtpv1_stn_sr_ie))||
		(NULL == CU_add_test(eSuite, "test of gtpv1 c_msisdn_ie()",
								test_encode_gtpv1_c_msisdn_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 extended_ranap_cause_ie()",
								test_encode_gtpv1_extended_ranap_cause_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 enodeb_id_ie()",
								test_encode_gtpv1_enodeb_id_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 node_identifier_ie()",
								test_encode_gtpv1_node_identifier_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 mbms_ue_context_ie()",
								test_encode_gtpv1_mbms_ue_context_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ue_ambr_ie()",
								test_encode_gtpv1_ue_ambr_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 auth_triplet_ie()",
								test_encode_gtpv1_auth_triplet_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 auth_quintuplet_ie()",
								test_encode_gtpv1_auth_quintuplet_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 src_rnc_pdcp_ctxt_info_ie()",
								test_encode_gtpv1_src_rnc_pdcp_ctxt_info_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 pdu_numbers_ie()",
								test_encode_gtpv1_pdu_numbers_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 extension_header_type_list_ie()",
								test_encode_gtpv1_extension_header_type_list_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ue_scef_pdn_connection_ie()",
								test_encode_gtpv1_ue_scef_pdn_connection_ie))		||
		(NULL == CU_add_test(eSuite, "test of gtpv1 mm_context_ie()",
								test_encode_gtpv1_mm_context_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 pdp_context_ie()",
								test_encode_gtpv1_pdp_context_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 ue_usage_type_ie()",
								test_encode_gtpv1_ue_usage_type_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 iov_updates_counter_ie()",
								test_encode_gtpv1_iov_updates_counter_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 teid_control_plane_ie()",
								test_encode_gtpv1_teid_control_plane_ie)) ||
		(NULL == CU_add_test(eSuite, "test of gtpv1 additional_rab_setup_info_ie()",
								test_encode_gtpv1_additional_rab_setup_info_ie)))
	{
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (    (NULL == CU_add_test(dSuite, "test of gtpv1 header()",
								test_decode_gtpv1_header))     ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 cause_ie()",
								test_decode_gtpv1_cause_ie))	||
		(NULL == CU_add_test(dSuite, "test of gtpv1 imsi_ie()", 
								test_decode_gtpv1_imsi_ie))          ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 routing_area_identity_ie()",
								test_decode_gtpv1_routing_area_identity_ie))  ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 reordering_req_ie()",
								test_decode_gtpv1_reordering_req_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 recovery_ie()",
								test_decode_gtpv1_recovery_ie))       ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 selection_mode_ie()",
								test_decode_gtpv1_selection_mode_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 teid_ie()",
								test_decode_gtpv1_teid_ie))||
		(NULL == CU_add_test(dSuite, "test of gtpv1 teardown_ind_ie()",
								test_decode_gtpv1_teardown_ind_ie))   ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 nsapi_ie()",      test_decode_gtpv1_nsapi_ie))  ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 chrgng_char_ie()",
								test_decode_gtpv1_chrgng_char_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 trace_reference_ie()",
								test_decode_gtpv1_trace_reference_ie))        ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 trace_type_ie()",
								test_decode_gtpv1_trace_type_ie))     ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 charging_id_ie()",
								test_decode_gtpv1_charging_id_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 end_user_addr_ie()",
								test_decode_gtpv1_end_user_address_ie))       ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 apn_ie()",
								test_decode_gtpv1_apn_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 protocol_config_options_ie()",
								test_decode_gtpv1_protocol_config_options_ie))        ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 gsn_addr_ie()", test_decode_gtpv1_gsn_addr_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 msisdn_ie()", test_decode_gtpv1_msisdn_ie))     ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 qos_ie()", test_decode_gtpv1_qos_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 traffic_flow_tmpl_ie()",
								test_decode_gtpv1_traffic_flow_tmpl_ie))      ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 trigger_id_ie()",
								test_decode_gtpv1_trigger_id_ie))     ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 omc_identity_ie()",
								test_decode_gtpv1_omc_identity_ie))   ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 common_flag_ie()",
								test_decode_gtpv1_common_flag_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 apn_restriction_ie()",
								test_decode_gtpv1_apn_restriction_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 rat_type_ie()",
								test_decode_gtpv1_rat_type_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 user_location_information_ie()",
								test_decode_gtpv1_user_location_information_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ms_time_zone_ie()",
								test_decode_gtpv1_ms_time_zone_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 imei_ie()",
								test_decode_gtpv1_imei_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 camel_charging_information_container_ie",
								test_decode_gtpv1_camel_charging_information_container_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 additional_trace_information_ie()",
								test_decode_gtpv1_additional_trace_information_ie))   ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ms_info_change_reporting_action_ie()",
								test_decode_gtpv1_ms_info_change_reporting_action_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 direct_tunnel_flag_ie()",
								test_decode_gtpv1_direct_tunnel_flag_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 correlation_id_ie()",
								test_decode_gtpv1_correlation_id_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 bearer_control_mode_ie()",
								test_decode_gtpv1_bearer_control_mode_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 evolved_allocation_retention_priority_1_ie()",
								test_decode_gtpv1_evolved_allocation_retention_priority_1_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 extended_common_flag_ie()",
								test_decode_gtpv1_extended_common_flag_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 user_csg_information_ie()",
								test_decode_gtpv1_user_csg_information_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 csg_information_reporting_action_ie()",
								test_decode_gtpv1_csg_information_reporting_action_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 apn_ambr_ie()",
								test_decode_gtpv1_apn_ambr_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ggsn_back_off_time_ie()",
								test_decode_gtpv1_ggsn_back_off_time_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 signalling_priority_indication_ie()",
								test_decode_gtpv1_signalling_priority_indication_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 uli_timestamp_ie()",
								test_decode_gtpv1_uli_timestamp_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 cn_operator_selection_entity_ie()",
								test_decode_gtpv1_cn_operator_selection_entity_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 extended_common_flags_2_ie()",
								test_decode_gtpv1_extended_common_flags_2_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 mapped_ue_usage_type_ie()",
								test_decode_gtpv1_mapped_ue_usage_type_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 up_function_selection_indication_ie()",
								test_decode_gtpv1_up_function_selection_indication_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 charging_gateway_addr_ie()",
								test_decode_gtpv1_charging_gateway_addr_ie))    ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 private_extension_ie()",
								test_decode_gtpv1_private_extension_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 map_cause_ie()",
								test_decode_gtpv1_map_cause_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ms_not_rechable_reason_ie()",
								test_decode_gtpv1_ms_not_rechable_reason_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 temporary_logical_link_identifie_ie()",
								test_decode_gtpv1_temporary_logical_link_identifier_ie))||
		(NULL == CU_add_test(dSuite, "test of gtpv1 packet_tmsi_ie()",
								test_decode_gtpv1_packet_tmsi_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 p_tmsi_signature_ie()",
								test_decode_gtpv1_p_tmsi_signature_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ms_validated_ie()",
								test_decode_gtpv1_ms_validated_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 sgsn_number_ie()",
								test_decode_gtpv1_sgsn_number_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 hop_counter_ie()",
								test_decode_gtpv1_hop_counter_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 rab_context_ie()",
								test_decode_gtpv1_rab_context_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 radio_priority_sms_ie()",
								test_decode_gtpv1_radio_priority_sms_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 radio_priority_ie()",
								test_decode_gtpv1_radio_priority_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 packet_flow_id_ie()",
								test_decode_gtpv1_packet_flow_id_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 radio_priority_lcs_ie()",
								test_decode_gtpv1_radio_priority_lcs_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 pdp_context_prioritization_ie()",
								test_decode_gtpv1_pdp_context_prioritization_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 rfsp_index_ie()",
								test_decode_gtpv1_rfsp_index_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 fqdn_ie()",
								test_decode_gtpv1_fqdn_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 evolved_allocation_retention_priority_II_ie()",
								test_decode_gtpv1_evolved_allocation_retention_priority_II_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ue_network_capability_ie()",
								test_decode_gtpv1_ue_network_capability_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 apn_ambr_with_nsapi_ie()",
								test_decode_gtpv1_apn_ambr_with_nsapi_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 signalling_priority_indication_with_nsapi_ie()",
								test_decode_gtpv1_signalling_priority_indication_with_nsapi_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 higher_bitrates_than_16_mbps_flag_ie()",
								test_decode_gtpv1_higher_bitrates_than_16_mbps_flag_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 selection_mode_with_nsapi_ie()",
								test_decode_gtpv1_selection_mode_with_nsapi_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 local_home_network_id_with_nsapi_ie()",
								test_decode_gtpv1_local_home_network_id_with_nsapi_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ran_transparent_container_ie()",
								test_decode_gtpv1_ran_transparent_container_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 rim_routing_addr_ie()",
								test_decode_gtpv1_rim_routing_addr_ie))||
		(NULL == CU_add_test(dSuite, "test of gtpv1 rim_routing_addr_disc_ie()",
								test_decode_gtpv1_rim_routing_addr_disc_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 selected_plmn_id_ie()",
								test_decode_gtpv1_selected_plmn_id_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 mbms_protocol_config_options_ie()",
								test_decode_gtpv1_mbms_protocol_config_options_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 teid_data_2_ie()",
								test_decode_gtpv1_teid_data_2_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ranap_cause_ie()",
								test_decode_gtpv1_ranap_cause_ie))||
		(NULL == CU_add_test(dSuite, "test of gtpv1 target_identification_ie()",
								test_decode_gtpv1_target_identification_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 utran_transparent_container_ie()",
								test_decode_gtpv1_utran_transparent_container_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 rab_setup_info_ie()",
								test_decode_gtpv1_rab_setup_info_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 bss_container_ie()",
								test_decode_gtpv1_bss_container_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 cell_identification_ie()",
								test_decode_gtpv1_cell_identification_ie))||
		(NULL == CU_add_test(dSuite, "test of gtpv1 bssgp_cause_ie()",
								test_decode_gtpv1_bssgp_cause_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 list_of_setup_pfcs_ie()",
								test_decode_gtpv1_list_of_setup_pfcs_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ps_handover_xid_param_ie()",
								test_decode_gtpv1_ps_handover_xid_param_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 reliable_inter_rat_handover_info_ie()",
								test_decode_gtpv1_reliable_inter_rat_handover_info_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 csg_id_ie()",
								test_decode_gtpv1_csg_id_ie))||
		(NULL == CU_add_test(dSuite, "test of gtpv1 csg_membership_indication_ie()",
								test_decode_gtpv1_csg_membership_indication_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 additional_mm_ctxt_for_srvcc_ie()",
								test_decode_gtpv1_additional_mm_ctxt_for_srvcc_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 additional_flags_for_srvcc_ie()",
								test_decode_gtpv1_additional_flags_for_srvcc_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 stn_sr_ie()",
								test_decode_gtpv1_stn_sr_ie))||
		(NULL == CU_add_test(dSuite, "test of gtpv1 c_msisdn_ie()",
								test_decode_gtpv1_c_msisdn_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 extended_ranap_cause_ie()",
								test_decode_gtpv1_extended_ranap_cause_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 enodeb_id_ie()",
								test_decode_gtpv1_enodeb_id_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 node_identifier_ie()",
								test_decode_gtpv1_node_identifier_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 mbms_ue_context_ie()",
								test_decode_gtpv1_mbms_ue_context_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ue_ambr_ie()",
								test_decode_gtpv1_ue_ambr_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 auth_triplet_ie()",
								test_decode_gtpv1_auth_triplet_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 auth_quintuplet_ie()",
								test_decode_gtpv1_auth_quintuplet_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 src_rnc_pdcp_ctxt_info_ie()",
								test_decode_gtpv1_src_rnc_pdcp_ctxt_info_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 pdu_numbers_ie()",
								test_decode_gtpv1_pdu_numbers_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 extension_header_type_list_ie()",
								test_decode_gtpv1_extension_header_type_list_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ue_scef_pdn_connection_ie()",
								test_decode_gtpv1_ue_scef_pdn_connection_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 mm_context_ie()",
								test_decode_gtpv1_mm_context_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 pdp_context_ie()",
								test_decode_gtpv1_pdp_context_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 ue_usage_type_ie()",
								test_decode_gtpv1_ue_usage_type_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 iov_updates_counter_ie()",
								test_decode_gtpv1_iov_updates_counter_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 teid_control_plane_ie()",
								test_decode_gtpv1_teid_control_plane_ie)) ||
		(NULL == CU_add_test(dSuite, "test of gtpv1 additional_rab_setup_info_ie()",
								test_decode_gtpv1_additional_rab_setup_info_ie)))
	{
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (    (NULL == CU_add_test(meSuite, "test of gtpv1 test_encode_gtpv1_echo_req()",
								test_encode_gtpv1_echo_req))     ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 test_encode_gtpv1_echo_rsp()",
								test_encode_gtpv1_echo_rsp))     ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 encode_version_not_supported()",
								test_encode_gtpv1_version_not_supported))     ||	
		(NULL == CU_add_test(meSuite, "test of gtpv1 supported_extension_headers_notification()",
						test_encode_gtpv1_supported_extension_headers_notification))  ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 create_pdp_ctxt_req()",
								test_encode_gtpv1_create_pdp_ctxt_req))     ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 create_pdp_ctxt_rsp()",
								test_encode_gtpv1_create_pdp_ctxt_rsp))     ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 update_pdp_ctxt_req_sgsn()",
								test_encode_gtpv1_update_pdp_ctxt_req_sgsn)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 update_pdp_ctxt_req_ggsn()",
								test_encode_gtpv1_update_pdp_ctxt_req_ggsn)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 update_pdp_ctxt_rsp_ggsn()",
								test_encode_gtpv1_update_pdp_ctxt_rsp_ggsn))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 update_pdp_ctxt_rsp_sgsn()",
								test_encode_gtpv1_update_pdp_ctxt_rsp_sgsn))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 delete_pdp_ctxt_req()",
								test_encode_gtpv1_delete_pdp_ctxt_req))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 delete_pdp_ctxt_rsp()",
								test_encode_gtpv1_delete_pdp_ctxt_rsp))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 pdu_notification_req()",
								test_encode_gtpv1_pdu_notification_req))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 pdu_notification_rsp()",
								test_encode_gtpv1_pdu_notification_rsp))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 pdu_notification_reject_req",
								test_encode_gtpv1_pdu_notification_reject_req))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 pdu_notification_reject_rsp()",
								test_encode_gtpv1_pdu_notification_reject_rsp))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 initiate_pdp_ctxt_active_req()",
								test_encode_gtpv1_initiate_pdp_ctxt_active_req))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 initiate_pdp_ctxt_active_rsp()",
								test_encode_gtpv1_initiate_pdp_ctxt_active_rsp))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 send_routeing_info_for_gprs_req()",
								test_encode_gtpv1_send_routeing_info_for_gprs_req))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 send_routeing_info_for_gprs_req()",
								test_encode_gtpv1_send_routeing_info_for_gprs_rsp))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 failure_report_req()",
								test_encode_gtpv1_failure_report_req))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 failure_report_rsp()",
								test_encode_gtpv1_failure_report_rsp))	||
		(NULL == CU_add_test(meSuite, "test of gtpv1 note_ms_gprs_present_req()",
								test_encode_gtpv1_note_ms_gprs_present_req)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 note_ms_gprs_present_rsp()",
								test_encode_gtpv1_note_ms_gprs_present_rsp)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 identification_req()",
								test_encode_gtpv1_identification_req)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 identification_rsp()",
								test_encode_gtpv1_identification_rsp)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 sgsn_context_ack()",
								test_encode_gtpv1_sgsn_context_ack)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 forward_relocation_complete()",
								test_encode_gtpv1_forward_relocation_complete)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 relocation_cancel_req()",
								test_encode_gtpv1_relocation_cancel_req)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 relocation_cancel_rsp()",
								test_encode_gtpv1_relocation_cancel_rsp)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 forward_relocation_complete_ack()",
								test_encode_gtpv1_forward_relocation_complete_ack)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 forward_srns_context_ack()",
								test_encode_gtpv1_forward_srns_context_ack)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 forward_srns_ctxt()",
								test_encode_gtpv1_forward_srns_ctxt)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 ran_info_relay()",
								test_encode_gtpv1_ran_info_relay)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 mbms_notification_req()",
								test_encode_gtpv1_mbms_notification_req)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 mbms_notification_rsp()",
								test_encode_gtpv1_mbms_notification_rsp)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 ms_info_change_notification_req()",
								test_encode_gtpv1_ms_info_change_notification_req)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 ms_info_change_notification_rsp()",
								test_encode_gtpv1_ms_info_change_notification_rsp)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 sgsn_ctxt_req()",
								test_encode_gtpv1_sgsn_ctxt_req)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 sgsn_ctxt_rsp()",
								test_encode_gtpv1_sgsn_ctxt_rsp)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 forward_relocation_req()",
								test_encode_gtpv1_forward_relocation_req)) ||
		(NULL == CU_add_test(meSuite, "test of gtpv1 forward_relocation_rsp()",
								test_encode_gtpv1_forward_relocation_rsp)))	
	{
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (    (NULL == CU_add_test(mdSuite, "test of gtpv1 echo_req()",
								test_decode_gtpv1_echo_req))     ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 echo_rsp()",
								test_decode_gtpv1_echo_rsp))     ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 version_not_supported()",
								test_decode_gtpv1_version_not_supported))     ||	
		(NULL == CU_add_test(mdSuite, "test of gtpv1 supported_extension_headers_notification()",
						test_decode_gtpv1_supported_extension_headers_notification))  ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 create_pdp_ctxt_req()",
								test_decode_gtpv1_create_pdp_ctxt_req))     ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 create_pdp_ctxt_rsp()",
								test_decode_gtpv1_create_pdp_ctxt_rsp))     ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 update_pdp_ctxt_req_sgsn()",
								test_decode_gtpv1_update_pdp_ctxt_req_sgsn)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 update_pdp_ctxt_req_ggsn()",
								test_decode_gtpv1_update_pdp_ctxt_req_ggsn)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 update_pdp_ctxt_rsp_ggsn()",
								test_decode_gtpv1_update_pdp_ctxt_rsp_ggsn))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 update_pdp_ctxt_rsp_sgsn()",
								test_decode_gtpv1_update_pdp_ctxt_rsp_sgsn))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 delete_pdp_ctxt_req()",
								test_decode_gtpv1_delete_pdp_ctxt_req))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 delete_pdp_ctxt_rsp()",
								test_decode_gtpv1_delete_pdp_ctxt_rsp))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 pdu_notification_req()",
								test_decode_gtpv1_pdu_notification_req))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 pdu_notification_rsp()",
								test_decode_gtpv1_pdu_notification_rsp))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 pdu_notification_reject_req",
								test_decode_gtpv1_pdu_notification_reject_req))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 pdu_notification_reject_rsp()",
								test_decode_gtpv1_pdu_notification_reject_rsp))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 initiate_pdp_ctxt_active_req()",
								test_decode_gtpv1_initiate_pdp_ctxt_active_req))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 initiate_pdp_ctxt_active_rsp()",
								test_decode_gtpv1_initiate_pdp_ctxt_active_rsp))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 send_routeing_info_for_gprs_req()",
								test_decode_gtpv1_send_routeing_info_for_gprs_req))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 send_routeing_info_for_gprs_req()",
								test_decode_gtpv1_send_routeing_info_for_gprs_rsp))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 failure_report_req()",
								test_decode_gtpv1_failure_report_req))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 failure_report_rsp()",
								test_decode_gtpv1_failure_report_rsp))	||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 note_ms_gprs_present_req()",
								test_decode_gtpv1_note_ms_gprs_present_req)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 note_ms_gprs_present_rsp()",
								test_decode_gtpv1_note_ms_gprs_present_rsp)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 identification_req()",
								test_decode_gtpv1_identification_req)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 identification_rsp()",
								test_decode_gtpv1_identification_rsp)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 sgsn_context_ack()",
								test_decode_gtpv1_sgsn_context_ack)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 forward_relocation_complete()",
								test_decode_gtpv1_forward_relocation_complete)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 relocation_cancel_req()",
								test_decode_gtpv1_relocation_cancel_req)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 relocation_cancel_rsp()",
								test_decode_gtpv1_relocation_cancel_rsp)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 forward_relocation_complete_ack()",
								test_decode_gtpv1_forward_relocation_complete_ack)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 forward_srns_context_ack()",
								test_decode_gtpv1_forward_srns_context_ack)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 forward_srns_ctxt()",
								test_decode_gtpv1_forward_srns_ctxt)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 ran_info_relay()",
								test_decode_gtpv1_ran_info_relay)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 mbms_notification_req()",
								test_decode_gtpv1_mbms_notification_req)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 mbms_notification_rsp()",
								test_decode_gtpv1_mbms_notification_rsp)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 ms_info_change_notification_req()",
								test_decode_gtpv1_ms_info_change_notification_req)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 ms_info_change_notification_rsp()",
								test_decode_gtpv1_ms_info_change_notification_rsp)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 sgsn_ctxt_req()",
								test_decode_gtpv1_sgsn_ctxt_req)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 sgsn_ctxt_rsp()",
								test_decode_gtpv1_sgsn_ctxt_rsp)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 forward_relocation_req()",
								test_decode_gtpv1_forward_relocation_req)) ||
		(NULL == CU_add_test(mdSuite, "test of gtpv1 forward_relocation_rsp()",
								test_decode_gtpv1_forward_relocation_rsp)))	
	{
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
