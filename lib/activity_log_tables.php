<?php

/***********************************************
Author: Adam Sewell
As Of: 0.1.7
Date: 02/03/19
Class: tinyShield_ActivityLog_Table
***********************************************/

if(!class_exists('WP_List_Table')){
  require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}

class tinyShield_ActivityLog_Table extends WP_List_Table{

	function __construct(){
		global $status, $page;

		parent::__construct(array(
			'singular' => 'list_item',
			'plurual' => 'list_items',
			'ajax' => false
		));
	}

	function column_default($item, $column_name){
		switch($column_name){
			default:
				return $item[$column_name];
		}
	}

	function column_iphash($item){
    $report_false_postiive_nonce = wp_create_nonce('tinyshield-report-false-positive');

		$actions = array(
			'report_false_positive' => sprintf('<a href="?page=%s&tab=log&action=%s&_wpnonce=%s&iphash=%s"> Report False Positive</a>', $_REQUEST['page'], 'report_false_positive', $report_false_postiive_nonce, ip2long($item['iphash'])),
		);

    //Return the title contents
    return sprintf('%1$s %3$s',
        /*$1%s*/ $item['iphash'],
        /*$2%s*/ $item['last_attempt'],
        /*$3%s*/ $this->row_actions($actions)
    );
	}

	function column_cb($item){
		return sprintf('<input type="checkbox" name="%1$s[]" value="%2$s" />', $this->_args['singular'], $item['iphash']);
	}

  function get_columns(){
  		$columns = array(
        'cb' => '<input type="checkbox" />',
  			'iphash' => 'IP Address',
        'rdns' => 'Hostname',
        'isp' => 'ISP',
        'origin' => 'Location',
        'action' => 'Action',
  			'direction' => 'Direction',
        'last_attempt' => 'Last Access'
  		);

		return $columns;
	}

	function get_sortable_columns() {
		$sortable_columns = array(
				'iphash'     => array('iphash', false),     //true means it's already sorted
				'last_attempt'    => array('last_attempt', true),

		);
		return $sortable_columns;
	}

	function prepare_items(){
		global $wpdb;
    $cached_whitelist = get_option('tinyshield_cached_whitelist');
    $cached_blacklist = get_option('tinyshield_cached_blacklist');
    $action_messages = array('allow' => '✅', 'block' => '⛔');
    $direction_icons = array('outbound' => 'Outbound', 'inbound' => 'Inbound');

		$per_page = 25;

		$columns = $this->get_columns();
		$hidden = array();
		$sortable = $this->get_sortable_columns();

		$this->_column_headers = array($columns, $hidden, $sortable);

		//massage data to conform to WordPress table standards
		$data = array();

    $logs = $cached_blacklist + $cached_whitelist;

    if(is_array($logs) && !empty($logs)){
			foreach($logs as $iphash => $iphash_data){
        $iphash_data = json_decode($iphash_data);
				$data[] = array(
          'action' => $action_messages[$iphash_data->action],
          'origin' =>  (!empty($iphash_data->geo_ip->region_name) ? $iphash_data->geo_ip->region_name . ', ' : '') . $iphash_data->geo_ip->country_name . ' ' . $iphash_data->geo_ip->country_flag_emoji,
					'iphash' => long2ip($iphash),
          'isp' => $iphash_data->geo_ip->isp,
          'direction' => $direction_icons[$iphash_data->direction],
          'last_attempt' => $iphash_data->last_attempt,
          'rdns' => (!empty($iphash_data->called_domain) ? $iphash_data->called_domain : $iphash_data->rdns)
				);
			}
    }

		$orderby = (isset($_GET['orderby']) && $_GET['orderby'] == 'iphash') ? 'iphash' : 'last_attempt'; //If no sort, default to title
		$order = (isset($_GET['order']) && strtolower($_GET['order']) == 'asc') ? SORT_ASC : SORT_DESC; //If no order, default to asc

    $iphash = array_column($data, 'iphash');
    $last_attempt = array_column($data, 'last_attempt');

    array_multisort($$orderby, $order, $data);

    //format the date now that we're sorted
    foreach($data as &$data_entry){
      if($data_entry['last_attempt']){
        $data_entry['last_attempt'] = date_i18n(get_option('date_format'), $data_entry['last_attempt']) . ' at ' . date_i18n(get_option('time_format'), $data_entry['last_attempt']);
      }
    }

		$current_page = $this->get_pagenum();

		$total_items = count($data);

		$data = array_slice($data, (($current_page-1) * $per_page), $per_page);

		$this->items = $data;

		$this->set_pagination_args( array(
			'total_items' => $total_items,                  //WE have to calculate the total number of items
			'per_page'    => $per_page,                     //WE have to determine how many items to show on a page
			'total_pages' => ceil($total_items/$per_page)   //WE have to calculate the total number of pages
		));

  }
} //end of tinyShield_WhiteList_Table
