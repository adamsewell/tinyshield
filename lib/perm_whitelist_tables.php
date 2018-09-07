<?php

/***********************************************
Author: Adam Sewell
As Of: 0.1.4
Date: 9/3/18
Class: tinyShield_PermWhiteList_Table
***********************************************/

if(!class_exists('WP_List_Table')){
  require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}

class tinyShield_PermWhiteList_Table extends WP_List_Table{

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
    $perm_whitelist_item_remove_nonce = wp_create_nonce('delete-tinyshield-perm-whitelist-item');
		$actions = array(
			'delete' => sprintf('<a href="?page=%s&tab=perm-whitelist&action=%s&_wpnonce=%s&iphash=%s">Remove from Permanent Whitelist</a>', $_REQUEST['page'], 'delete-perm-whitelist', $perm_whitelist_item_remove_nonce, ip2long($item['iphash']))
		);

    //Return the title contents
    return sprintf('%1$s %3$s',
        /*$1%s*/ $item['iphash'],
        /*$2%s*/ $item['expires'],
        /*$3%s*/ $this->row_actions($actions)
    );

    // return sprintf('%1$s <span style="color:silver">(id:%2$s)</span>%3$s',
    //     /*$1%s*/ $item['iphash'],
    //     /*$2%s*/ $item['expires'],
    //     /*$3%s*/ $this->row_actions($actions)
    // );
	}

	function column_cb($item){
		return sprintf('<input type="checkbox" name="%1$s[]" value="%2$s" />', $this->_args['singular'], $item['iphash']);
	}

	function get_columns(){
		$columns = array(
			'cb' => '<input type="checkbox" />',
			'iphash' => 'IP Address',
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
    $cached_perm_whitelist = get_option('tinyshield_cached_perm_whitelist');

		$per_page = 25;

		$columns = $this->get_columns();
		$hidden = array();
		$sortable = $this->get_sortable_columns();

		$this->_column_headers = array($columns, $hidden, $sortable);

		//massage data to conform to WordPress table standards
		$data = array();

		if(is_array($cached_perm_whitelist) && !empty($cached_perm_whitelist)){
			foreach($cached_perm_whitelist as $iphash => $iphash_data){
        $iphash_data = json_decode($iphash_data);
				$data[] = array(
					'iphash' => long2ip($iphash),
          'expires' => date(get_option('date_format'), $iphash_data->expires) . ' at ' . date(get_option('time_format'), $iphash_data->expires)
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
} //end of tinyShield_PermWhiteList_Table
