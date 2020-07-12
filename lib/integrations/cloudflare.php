<?php

  class tinyShieldCloudFlare extends tinyShield{
    public function __construct(){
      $api_url = 'https://api.cloudflare.com/client/v4/';
    }

    public static function create_access_rule($ip){
      $options = get_option('tinyshield_options');

      $response = wp_remote_post(
        $this->api_url . '/user/firewall/access_rules/rules',
        array(
          'headers' => array(
            'X-Auth-Email:' => 'adam@tinyshield.me',
            'X-Auth-Key:' => 'YlC14t4bPvhi3tEwjH9kcnWeU0Lx2zgyHoNM5B_y',
            'Content-Type:' => 'application/json'
          ),
          'body' => json_encode(
            array(
              'mode' => 'challenge',
              'configuration' => array(
                'target' => 'ip',
                'value' => $ip
              ),
              'notes' => 'tinyShield Blocked On: ' . current_time('mysql')
            )
          )
        )
      );

      if(is_wp_error($response)){
        self::write_log('tinyShield: cloudflare remote post error '. $response->get_error_message());
        return false;
      }else{
        $return = json_decode($response, true);
        self::write_log('tinyShield: cloudflare remote post success');
        self::write_log($return);

        if(isset($return['success']) && $return['success'] == true){
			       return $return['result']['id'];
		    }else{
			       return false;
		    }
      }

    }

    public static function delete_access_rule($ip){

    }
  }
