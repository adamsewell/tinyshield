<?php

/***********************************************
Author: Adam Sewell
As Of: 0.1.4
Date: 9/3/18
Class: tinyShield_BlockList_Table
***********************************************/

if(!class_exists('WP_List_Table')){
  require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}

class tinyShield_BlockList_Table extends WP_List_Table{

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

	function column_ip_address($item){
    $move_item_to_perm_allowlist_nonce = wp_create_nonce('tinyshield-move-item-perm-allowlist');
    $move_item_to_allowlist_nonce = wp_create_nonce('tinyshield-move-item-allowlist');
    $blocklist_item_remove_nonce = wp_create_nonce('tinyshield-delete-blocklist-item');

		$actions = array(
      'add_to_allowlist' => sprintf('<a href="?page=%s&tab=blocklist&action=%s&_wpnonce=%s&iphash=%s">Allowlist</a>',$_REQUEST['page'], 'add_to_allowlist', $move_item_to_allowlist_nonce, $item['iphash']),
			'add_to_perm_allowlist' => sprintf('<a href="?page=%s&tab=blocklist&action=%s&_wpnonce=%s&iphash=%s">Permanent Allowlist</a>',$_REQUEST['page'], 'add_to_perm_allowlist', $move_item_to_perm_allowlist_nonce, $item['iphash']),
      'delete' => sprintf('<a href="?page=%s&tab=blocklist&action=%s&_wpnonce=%s&iphash=%s">Remove from Blocklist</a>', $_REQUEST['page'], 'remove_from_blocklist', $blocklist_item_remove_nonce, $item['iphash'])
		);

    //Return the title contents
    return sprintf('%1$s %3$s',
        /*$1%s*/ $item['ip_address'],
        /*$2%s*/ $item['expires'],
        /*$3%s*/ $this->row_actions($actions)
    );
	}

	function column_cb($item){
		return sprintf('<input type="checkbox" name="%1$s[]" value="%2$s" />', $this->_args['singular'], $item['iphash']);
	}

	function get_columns(){
		$columns = array(
      'cb' => '<input type="checkbox" />',
			'ip_address' => 'IP Address',
      'rdns' => 'Hostname',
      'isp' => 'ISP',
      'origin' => 'Location',
			'expires' => 'Expires',
      'last_attempt' => 'Last Access'
		);

		return $columns;
	}

	function get_sortable_columns() {
		$sortable_columns = array(
				'ip_address'     => array('ip_address', false),     //true means it's already sorted
        'last_attempt' => array('last_attempt', false),
				'expires'    => array('expires', false),
		);
		return $sortable_columns;
	}

	function prepare_items(){
		$cached_blocklist = get_option('tinyshield_cached_blocklist');

		$per_page = 25;
    $community_message = __('📡 <span style="color: orange">Premium Access Required</span> 🌎', 'tinyshield');

		$columns = $this->get_columns();
		$hidden = array();
		$sortable = $this->get_sortable_columns();

		$this->_column_headers = array($columns, $hidden, $sortable);

		//massage data to conform to WordPress table standards
		$data = array();

		if(is_array($cached_blocklist) && !empty($cached_blocklist)){
			foreach($cached_blocklist as $iphash => $iphash_data){
        $iphash_data = json_decode($iphash_data);
				$data[] = array(
					'iphash' => $iphash,
          'ip_address' => $iphash_data->ip_address,
          'expires' => $iphash_data->expires,
          'last_attempt' => $iphash_data->last_attempt,
          'isp' => (!empty($iphash_data->geo_ip) ? $iphash_data->geo_ip->isp : $community_message),
          'origin' =>  (!empty($iphash_data->geo_ip->region_name) ? $iphash_data->geo_ip->region_name . ', ' : '') . (!empty($iphash_data->geo_ip) ? $iphash_data->geo_ip->country_name . ' ' . $iphash_data->geo_ip->country_flag_emoji : $community_message),
          'rdns' => $iphash_data->rdns
				);
			}
    }

    $orderby = (isset($_GET['orderby']) && $_GET['orderby'] == 'ip_address') ? 'ip_address' : 'expires'; //If no sort, default to title
		$order = (isset($_GET['order']) && $_GET['order'] == 'asc') ? SORT_ASC : SORT_DESC; //If no order, default to asc

    $ip_address = array_column($data, 'ip_address');
    $expires = array_column($data, 'expires');
    $last_attempt = array_column($data, 'last_attempt');

    array_multisort($$orderby, $order, $data);

    //format the date now that we're sorted
    foreach($data as &$data_entry){
      if($data_entry['last_attempt']){
        $data_entry['last_attempt'] = wp_date(get_option('date_format'), $data_entry['last_attempt']) . ' at ' . wp_date(get_option('time_format'), $data_entry['last_attempt']);
      }
      if($data_entry['expires']){
        $data_entry['expires'] = wp_date(get_option('date_format'), $iphash_data->expires) . ' at ' . wp_date(get_option('time_format'), $iphash_data->expires);
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
} //end of tinyShield_List_Table
