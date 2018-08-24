<?php
use GuzzleHttp\Client;
use GuzzleHttp\Message\Request;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Psr7;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ClientException;


class Api_forti {
	var $ci;
	protected $client;
	protected $token;

	function __construct()
	{
		$this->ci =& get_instance();
		$login = $this->login_fortinet();
		$this->client = $login['client'];
		$this->token = $login['token'];
	}
	
    private function login_fortinet() {
       
		try {
			$client = new Client(['base_uri' => 'http://mywebsite','timeout'  => 5.0, 'cookies' => true, 'verify' => false, 'headers' => ['User-Agent' => 'API']]);
			$r = $client->request('POST', '' . $this->ci->config->item('forti_url') . '/logincheck',['form_params' => ['username' => 'admin', 'secretkey' => 'password']]);
			if(isset($r->getHeaders()['Set-Cookie'])){
				foreach ($r->getHeaders()['Set-Cookie']as $v) {
					if (preg_match('/ccsrftoken="(.*)"/', $v, $o)) {
						$token = $o[1];
					}
				}
				return array('client' => $client, 'token' => $token);
			}
	

		}
		catch (ConnectException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (RequestException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (ClientException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (BadResponseException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (ServerException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}			
    }
	
	public function request_fortinet($options){
	
		try {
			if($options['method'] == 'POST' OR $options['method'] == 'PUT'){
				return $this->client->$options['method']('' . $this->ci->config->item('forti_url') . '' . $options['patch'] . '', [ 'headers' => [ 'X-CSRFTOKEN' => $this->token], 'body' => $options['json'] ]);
			} elseif($options['method'] == 'DELETE' OR $options['method'] == 'GET'){
				return $this->client->$options['method']('' . $this->ci->config->item('forti_url') . '' . $options['patch'] . '', [ 'headers' => [ 'X-CSRFTOKEN' => $this->token]]);
			}
		}
		catch (ConnectException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (RequestException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (ClientException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (BadResponseException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}
		catch (ServerException $e) {
			$this->ci->db->update('config', array('daemon' => 'offline'));
			$this->ci->db->insert('logs', array('error' => json_encode($e->gethandlerContext()), 'debug' => json_encode( (array)$e ), 'date' => date('Y-m-d H:i:s')));
		}				
	}

    public function add_firewall_policy($params) {
		$json = new stdClass();
        if (!empty($params['vdom'])) {
            $json->vdom = $params['vdom'];
        } else {
            // $json->vdom = 'root';
        }
		
		$json->json = new stdClass();
		$json->json->name = $params['name'];
		$json->json->policyid = $params['name'];

		$json->json->srcintf = array();
        if (!empty($params['srcintf'])) {
			$json->json->srcintf[]['name'] = $params['srcintf'];
        } else {
			$json->json->srcintf[]['name'] = 'any';
        }
		
		$json->json->dstintf = array();
        if (!empty($params['dstintf'])) {
            $json->json->dstintf[]['name'] = $params['dstintf'];
        } else {
            $json->json->dstintf[]['name'] = 'any';
        }
		
		$json->json->srcaddr = array();
        if (!empty($params['srcaddr'])) {
            $json->json->srcaddr[]['name'] = $params['srcaddr'];
        } else {
            $json->json->srcaddr[]['name'] = 'all';
        }
		
		$json->json->dstaddr = array();
        if (!empty($params['dstaddr'])) {
            $json->json->dstaddr[]['name'] = $params['dstaddr'];
        } else {
           // $json->json->dstaddr[]['name'] = 'all';
        }
		
        if (!empty($params['action'])) {
            $json->json->action = $params['action'];
        } else {
			$json->json->action = "accept";
        }
		
		$json->json->schedule = "always";
        if (!empty($params['nat'])) {
			$json->json->nat = $params['nat'];
        }
		
        if (!empty($params['poolname'])) {
            if (!empty($params['nat'])) {
				$json->json->nat = "enable";
            } else {
				$json->json->ippool = "enable";
				$json->json->poolname = array();
				$json->json->poolname[]['name'] = $params['poolname'];
            }
        }
        if (!empty($params['match_vip'])) {
			$json->json->{'match-vip'} = $params['match_vip'];
        } else {
			$json->json->{'match-vip'} = "disable";
        }
        if (!empty($params['status'])) {
			$json->json->status = $params['status'];
        } else {
			$json->json->status = "enable";
        }
		$json->json->service = array();
        if (!empty($params['service'])) {
			$json->json->service[]['name'] = $params['service'];
        } else {
			$json->json->service[]['name'] = "ALL";
        }
		
		$json->json->{'av-profile'} = "";
		$json->json->{'webfilter-profile'} = "";
		$json->json->{'ips-sensor'} = "";
		$json->json->{'application-list'} = "";
		$json->json->{'ssl-ssh-profile'} = "";
		$json->json->{'utm-status'} = "disable";
		$json->json->{'profile-protocol-options'} = "";
		$json->json->logtraffic = 'disable';
		
			
        if (!empty($params['comments'])) {
			$json->json->comments = $params['comments'];
        } else {
			$json->json->comments = "";
        }

		$json = json_encode( (array)$json );
		
        return $this->request_fortinet(array('json' => $json, 'patch' => '/api/v2/cmdb/firewall/policy/', 'method' => 'POST'));
    }

   public function set_firewall_policy($vdom, $id, $params) {
	   
        if ($vdom) {
            $url = "/api/v2/cmdb/firewall/policy/$id/?vdom=$vdom";
        } else {
            $url = "/api/v2/cmdb/firewall/policy/$id";
        }	   
	   
		$json = new stdClass();
        if (!empty($vdom)) {
            $json->vdom = $vdom;
        } else {
            // $json->vdom = 'root';
        }
		
		$json->json = new stdClass();
		$json->json->name = $id;
		$json->json->policyid = $id;

		$json->json->srcintf = array();
        if (!empty($params['srcintf'])) {
			$json->json->srcintf[]['name'] = $params['srcintf'];
        } else {
			$json->json->srcintf[]['name'] = 'any';
        }
		
		$json->json->dstintf = array();
        if (!empty($params['dstintf'])) {
            $json->json->dstintf[]['name'] = $params['dstintf'];
        } else {
            $json->json->dstintf[]['name'] = 'any';
        }
		
		$json->json->srcaddr = array();
        if (!empty($params['srcaddr'])) {
            $json->json->srcaddr[]['name'] = $params['srcaddr'];
        } else {
            $json->json->srcaddr[]['name'] = 'all';
        }
		
		$json->json->dstaddr = array();
        if (!empty($params['dstaddr'])) {
            $json->json->dstaddr[]['name'] = $params['dstaddr'];
        } else {
            //$json->json->dstaddr[]['name'] = 'all';
        }
		
        if (!empty($params['action'])) {
            $json->json->action = $params['action'];
        } else {
			$json->json->action = "accept";
        }
		
		$json->json->schedule = "always";
        if (!empty($params['nat'])) {
			$json->json->nat = $params['nat'];
        }
		
        if (!empty($params['poolname'])) {
            if (!empty($params['nat'])) {
				$json->json->nat = "enable";
            } else {
				$json->json->ippool = "enable";
				$json->json->poolname = array();
				$json->json->poolname[]['name'] = $params['poolname'];
            }
        }
        if (!empty($params['match_vip'])) {
			$json->json->{'match-vip'} = $params['match_vip'];
        } else {
			$json->json->{'match-vip'} = "disable";
        }
        if (!empty($params['status'])) {
			$json->json->status = $params['status'];
        } else {
			$json->json->status = "enable";
        }
		$json->json->service = array();
        if (!empty($params['service'])) {
			$json->json->service[]['name'] = $params['service'];
        } else {
			$json->json->service[]['name'] = "ALL";
        }
		
		$json->json->{'av-profile'} = "";
		$json->json->{'webfilter-profile'} = "";
		$json->json->{'ips-sensor'} = "";
		$json->json->{'application-list'} = "";
		$json->json->{'ssl-ssh-profile'} = "";
		$json->json->{'utm-status'} = "disable";
		$json->json->{'profile-protocol-options'} = "";
		$json->json->logtraffic = 'disable';
		
			
        if (!empty($params['comments'])) {
			$json->json->comments = $params['comments'];
        } else {
			$json->json->comments = "";
        }

		$json = json_encode( (array)$json );
		
        return $this->request_fortinet(array('json' => $json, 'patch' => $url, 'method' => 'PUT'));
    }	
	
    public function delete_firewall_policy($vdom, $id) {
        if ($vdom) {
            $url = "/api/v2/cmdb/firewall/policy/$id/?vdom=$vdom";
        } else {
            $url = "/api/v2/cmdb/firewall/policy/$id";
        }

        return $this->request_fortinet(array('patch' => $url, 'method' => 'DELETE'));
    }

    public function get_firewall_policy($vdom, $id) {
        if ($id) {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall/policy/$id/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall/policy/$id/";
            }
        } else {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall/policy/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall/policy/";
            }
        }
        return $this->request_fortinet(array('patch' => $url, 'method' => 'GET'));
    }


    public function move_firewall_policy($vdom, $id, $before = null, $after = null) {
        if ($vdom) {
            $url = "/api/v2/cmdb/firewall/policy/$id/?vdom=$vdom";
        } else {
            $url = "/api/v2/cmdb/firewall/policy/$id";
        }
		
		$json = new stdClass();
	
        if ($before) {
            $json->before = $before;
        } else {
			$json->after = $after;
        }
        
		$json->action = "move";
		
		$json = json_encode( (array)$json );
		
        return $this->request_fortinet(array('json' => $json, 'patch' => $url, 'method' => 'PUT'));

    }

    public function add_firewall_service($params) {
		$json = new stdClass();
		
        if ($params['vdom']) {
            $json->vdom = $params['vdom'];
        } else {
            // $json->vdom = 'root';
        }

		$json->name = 'custom';

        $json->json = new stdClass();
        if (!empty($params['protocol'])) {
			$json->json->protocol = $params['protocol'];
        } else {
			$json->json->protocol = "TCP/UDP/SCTP";
        }
        if (!empty($params['fqdn'])) {
			$json->json->fqdn = $params['fqdn'];
        }
        if (!empty($params['category'])) {
			$json->json->category = $params['category'];
        }
        if (!empty($params['iprange'])) {
			$json->json->iprange = $params['iprange'];
        }
        if (!empty($params['tcp_portrange'])) {
			$json->json->{'tcp-portrange'} = $params['tcp_portrange'];
        }
        if (!empty($params['udp_portrange'])) {
			$json->json->{'udp-portrange'} = $params['udp_portrange'];
        }
        if (!empty($params['sctp_portrange'])) {
			$json->json->{'sctp-portrange'} = $params['udp_portrange'];
        }
        if (!empty($params['comment'])) {
			$json->json->comment = $params['comment'];
        }
		$json->json->name = $params['name'];
		
		$json = json_encode( (array)$json );

        return $this->request_fortinet(array('json' => $json, 'patch' => '/api/v2/cmdb/firewall.service/custom/', 'method' => 'POST'));
    }

    public function delete_firewall_service($vdom, $name) {
        if ($vdom) {
            $url = "/api/v2/cmdb/firewall.service/custom/$name/?vdom=$vdom";
        } else {
            $url = "/api/v2/cmdb/firewall.service/custom/$name";
        }
        return $this->request_fortinet(array('patch' => $url, 'method' => 'DELETE'));
    }

    public function get_firewall_service($vdom, $name, $id) {
        if ($name) {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall.service/custom/$name/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall.service/custom/$name/";
            }
        } else {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall.service/custom/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall.service/custom/";
            }
        }
        return $this->request_fortinet(array('patch' => $url, 'method' => 'GET'));
    }

	
	
    public function add_firewall_address($params) {
		$json = new stdClass();
		
        if ($params['vdom']) {
            $json->vdom = $params['vdom'];
        } else {
            // $json->vdom = 'root';
        }

		$json->name = 'address';		
        $json->json = new stdClass();
		if (!empty($params['type'])) {
			$json->json->type = $params['type'];
		}			
        if (!empty($params['associated_interface'])) {
			$json->json->{'associated-interface'} = $params['associated_interface'];
        }
        if (!empty($params['comment'])) {
			$json->json->comment = $params['comment'];
        }
		if (!empty($params['subnet'])) {
			$json->json->subnet = $params['subnet'];
		}
		if (!empty($params['country'])) {
			$json->json->country = $params['country'];
		}		
		$json->json->name = $params['name'];

		$json = json_encode( (array)$json );
		
        return $this->request_fortinet(array('json' => $json, 'patch' => '/api/v2/cmdb/firewall/address/', 'method' => 'POST'));
    }

    public function set_firewall_address($vdom, $id, $params) {
		$json = new stdClass();
		
        if ($vdom) {
            $url = "/api/v2/cmdb/firewall/address/$id/?vdom=$vdom";
        } else {
            $url = "/api/v2/cmdb/firewall/address/$id";
        }	   
	   
		$json = new stdClass();
        if (!empty($vdom)) {
            $json->vdom = $vdom;
        } else {
            // $json->vdom = 'root';
        }

		$json->name = 'address';		
        $json->json = new stdClass();
		if (!empty($params['type'])) {
			$json->json->type = $params['type'];
		}			
        if (!empty($params['associated_interface'])) {
			$json->json->{'associated-interface'} = $params['associated_interface'];
        }
        if (!empty($params['comment'])) {
			$json->json->comment = $params['comment'];
        }
		if (!empty($params['subnet'])) {
			$json->json->subnet = $params['subnet'];
		}
		if (!empty($params['country'])) {
			$json->json->country = $params['country'];
		}		
		$json->json->name = $params['name'];

		$json = json_encode( (array)$json );
		
        return $this->request_fortinet(array('json' => $json, 'patch' => $url, 'method' => 'PUT'));
    }	
	
    public function delete_firewall_address($vdom, $name) {
        if ($vdom) {
            $url = "/api/v2/cmdb/firewall/address/$name/?vdom=$vdom";
        } else {
            $url = "/api/v2/cmdb/firewall/address/$name";
        }
        return $this->request_fortinet(array('patch' => $url, 'method' => 'DELETE'));
    }

    public function get_firewall_address($vdom, $name) {
        if ($name) {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall/address/$name/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall/address/$name/";
            }
        } else {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall/address/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall/address/";
            }
        }
        return $this->request_fortinet(array('patch' => $url, 'method' => 'GET'));
    }
	
	public function add_firewall_addrgrp($params){
		$json = new stdClass();
		
        if ($params['vdom']) {
            $json->vdom = $params['vdom'];
        } else {
            // $json->vdom = 'root';
        }

		$json->name = 'addrgrp';		
        $json->json = new stdClass();

		$json->json->name = $params['name'];
		$json->json->member = array();
       
		foreach($params['member'] as $i => $v){
			$json->json->member[$i]['name'] = $v;
		}

        if (!empty($params['comment'])) {
			$json->json->comment = $params['comment'];
        }	   		
		
		$json = json_encode( (array)$json );
		
		return $this->request_fortinet(array('json' => $json, 'patch' => '/api/v2/cmdb/firewall/addrgrp/', 'method' => 'POST'));	
    }	

    public function delete_firewall_addrgrp($vdom, $name) {
        if ($vdom) {
            $url = "/api/v2/cmdb/firewall/addrgrp/$name/?vdom=$vdom";
        } else {
            $url = "/api/v2/cmdb/firewall/addrgrp/$name";
        }
        return $this->request_fortinet(array('patch' => $url, 'method' => 'DELETE'));
    }

    public function get_firewall_addrgrp($vdom, $name) {
        if ($name) {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall/addrgrp/$name/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall/addrgrp/$name/";
            }
        } else {
            if ($vdom) {
                $url = "/api/v2/cmdb/firewall/addrgrp/?vdom=$vdom";
            } else {
                $url = "/api/v2/cmdb/firewall/addrgrp/";
            }
        }
        return $this->request_fortinet(array('patch' => $url, 'method' => 'GET'));
    }
	
    public function logout() {
        return $this->request_fortinet(array('patch' => '/logout', 'method' => 'GET'));
    }	
}
