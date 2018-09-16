<?php

/***********************************************
Author: Adam Sewell
As Of: 0.1.4
Date: 9/3/18
Class: tinyShield_BlackList_Table
***********************************************/

if(!class_exists('WP_List_Table')){
  require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}

class tinyShield_BlackList_Table extends WP_List_Table{

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
    $move_item_to_perm_whitelist_nonce = wp_create_nonce('tinyshield-move-item-perm-whitelist');
    $move_item_to_whitelist_nonce = wp_create_nonce('tinyshield-move-item-whitelist');
    $blacklist_item_remove_nonce = wp_create_nonce('tinyshield-delete-blacklist-item');

		$actions = array(
      'add_to_whitelist' => sprintf('<a href="?page=%s&tab=blacklist&action=%s&_wpnonce=%s&iphash=%s">Whitelist</a>',$_REQUEST['page'], 'add_to_whitelist', $move_item_to_whitelist_nonce, ip2long($item['iphash'])),      
			'add_to_perm_whitelist' => sprintf('<a href="?page=%s&tab=blacklist&action=%s&_wpnonce=%s&iphash=%s">Permanent Whitelist</a>',$_REQUEST['page'], 'add_to_perm_whitelist', $move_item_to_perm_whitelist_nonce, ip2long($item['iphash'])),
      'delete' => sprintf('<a href="?page=%s&tab=blacklist&action=%s&_wpnonce=%s&iphash=%s">Remove from Blacklist</a>', $_REQUEST['page'], 'remove_from_blacklist', $blacklist_item_remove_nonce, ip2long($item['iphash']))
		);

    //Return the title contents
    return sprintf('%1$s %3$s',
        /*$1%s*/ $item['iphash'],
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
			'iphash' => 'IP Address',
      'rdns' => 'Hostname',
      'origin' => 'Location',
			'expires' => 'Expires'
		);

		return $columns;
	}

	function get_sortable_columns() {
		$sortable_columns = array(
				'iphash'     => array('iphash', false),     //true means it's already sorted
				'expires'    => array('expires', false),
		);
		return $sortable_columns;
	}

	function prepare_items(){
		global $wpdb;
		$cached_blacklist = get_option('tinyshield_cached_blacklist');

		$per_page = 25;

		$columns = $this->get_columns();
		$hidden = array();
		$sortable = $this->get_sortable_columns();

		$this->_column_headers = array($columns, $hidden, $sortable);

		//massage data to conform to WordPress table standards
		$data = array();

		if(is_array($cached_blacklist) && !empty($cached_blacklist)){
			foreach($cached_blacklist as $iphash => $iphash_data){
        $iphash_data = json_decode($iphash_data);
				$data[] = array(
					'iphash' => long2ip($iphash),
          'expires' => date(get_option('date_format'), $iphash_data->expires) . ' at ' . date(get_option('time_format'), $iphash_data->expires),
          'origin' => $iphash_data->geo_ip->country_flag_emoji . ' ' . $iphash_data->geo_ip->country_name,
          'rdns' => $iphash_data->rdns
				);
			}
    }

    $orderby = (isset($_GET['orderby']) && $_GET['orderby'] == 'iphash') ? 'iphash' : 'expires'; //If no sort, default to title
		$order = (isset($_GET['order']) && $_GET['order'] == 'asc') ? SORT_ASC : SORT_DESC; //If no order, default to asc

    $iphash = array_column($data, 'iphash');
    $expires = array_column($data, 'expires');

    array_multisort($$orderby, $order, $data);

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
