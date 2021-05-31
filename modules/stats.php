<?php

  add_action('tinyshield_block_ip', 'tinyShield_Module_Stats::add_stats');
  add_action('tinyshield_allow_ip', 'tinyShield_Module_Stats::add_stats');

  class tinyShield_Module_Stats extends tinyShield{

    public static function add_stats($data){
      $options = get_option('tinyshield_options');

      if(empty($options['tinyshield_stats'])){
        if($data->action == 'allow'){
          $options['tinyshield_stats'] = serialize(
            array('allowed' => array(
              strtotime('today') => 1,
            )
          ));
        }elseif($data->action == 'block'){
          $options['tinyshield_stats'] = serialize(
            array('blocked' => array(
              strtotime('today') => 1,
            )
          ));
        }
        
        update_option('tinyshield_options', $options);
      }else{
        $stats = unserialize($options['tinyshield_stats']);

        if(is_array($stats)){
          if($data->action == 'allow'){
            $stats['allowed'][strtotime('today')]++;
          }elseif($data->action == 'block'){
            $stats['blocked'][strtotime('today')]++;
          }
        }

        $options['tinyshield_stats'] = serialize($stats);
        update_option('tinyshield_options', $options);
      }

      return true;
    }
  }
