class mcollective (
  $configure_agent = false,
  $configure_client = true,
  $configure_puppet_agent_plugin = true,
  $configure_rabbit_vhost = false,

  $confdir = '/etc/puppetlabs/mcollective',

  $rabbit_host,
  $rabbit_port,
  $rabbit_ssl = false,
  $rabbit_ssl_cacert = '',
  $rabbit_ssl_cert = '',
  $rabbit_ssl_key = '',
  $rabbit_ssl_ciphers = 'DHE-RSA-AES256-SHA',

  $rabbit_user,
  $rabbit_password,

  $rabbit_admin_user = false,     # only required if $configure_rabbit_vhost
  $rabbit_admin_password = false, # ^

  $enable_agent_service = true,

  $mcollective_pre_shared_key = 'unset',
) {

  if ($configure_agent) {
    include mcollective::agent
  }

  if ($configure_client) {
    include mcollective::client
  }

  if ($configure_puppet_agent_plugin) {
    include mcollective::puppet_agent

    if ($configure_agent) {
      Class['mcollective::puppet_agent'] ~> Service['mcollective']
    }
  }

  if ($configure_rabbit_vhost) {
    if (!$rabbit_admin_user) {
      fail('mcollective::rabbit_admin_user must be configured')
    }

    if (!$rabbit_admin_password) {
      fail('mcollective::rabbit_admin_password must be configured')
    }

    include mcollective::rabbit_vhost
  }
}

# (mcollective is already installed because puppet 4 is already installed...)

class mcollective::agent {
  include mcollective::agent::config, mcollective::agent::service, mcollective::agent::sync_facts
}

class mcollective::agent::config {
  $servercfg = "$mcollective::confdir/server.cfg"

  Ini_setting {
    path    => "$mcollective::confdir/server.cfg",
  }

  ini_setting { "mcollective/server.cfg/connector":
    setting => 'connector',
    value   => 'rabbitmq',
  }

  ini_setting { "mcollective/server.cfg/identity":
    setting => 'identity',
    value   => $fqdn,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.vhost":
    setting => 'plugin.rabbitmq.vhost',
    value   => '/mcollective',
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.size":
    setting => 'plugin.rabbitmq.pool.size',
    value   => '1',
  }
  
  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.host":
    setting => 'plugin.rabbitmq.pool.1.host',
    value   => $mcollective::rabbit_host,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.port":
    setting => 'plugin.rabbitmq.pool.1.port',
    value   => $mcollective::rabbit_port,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.user":
    setting => 'plugin.rabbitmq.pool.1.user',
    value   => $mcollective::rabbit_user,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.password":
    setting => 'plugin.rabbitmq.pool.1.password',
    value   => $mcollective::rabbit_password,
  }

  $ssl_ensure = $mcollective::rabbit_ssl ? {
    true => present,
    default => absent,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.ssl":
    setting => 'plugin.rabbitmq.pool.1.ssl',
    value   => $mcollective::rabbit_ssl ? {
      true => '1',
      default => '0',
    },
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.ssl.ciphers":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.ciphers',
    value   => $mcollective::rabbit_ssl_ciphers,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.ssl.ca":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.ca',
    value   => $mcollective::rabbit_ssl_cacert,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.ssl.cert":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.cert',
    value   => $mcollective::rabbit_ssl_cert,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.ssl.key":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.key',
    value   => $mcollective::rabbit_ssl_key,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.pool.1.ssl.fallback":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.fallback',
    value   => 0,
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.heartbeat_interval":
    setting => 'plugin.rabbitmq.heartbeat_interval',
    value   => '120',
  }

  ini_setting { "mcollective/server.cfg/plugin.rabbitmq.stomp_1_0_fallback":
    setting => 'plugin.rabbitmq.stomp_1_0_fallback',
    value   => '0',
  }

  ini_setting { "mcollective/server.cfg/factsource":
    setting => 'factsource',
    value   => 'yaml',
  }

  ini_setting { "mcollective/server.cfg/plugin.yaml":
    setting => 'plugin.yaml',
    value   => "$mcollective::confdir/facts.yaml",
  }

  ini_setting { "mcollective/server.cfg/classesfile":
    setting => 'classesfile',
    value   => '/opt/puppetlabs/puppet/cache/state/classes.txt',
  }

  ini_setting { 'mcollective/server.cfg/plugin.psk':
    setting => 'plugin.psk',
    value => $mcollective::mcollective_pre_shared_key,
  }
}

Class['mcollective::agent::config'] ~> Service['mcollective']

class mcollective::agent::sync_facts {
  file { "$mcollective::confdir/facts.yaml":
    loglevel => debug, # reduce noise in Puppet reports
    # exclude rapidly changing facts
    content  => inline_template("<%= scope.to_hash.reject { |k,v| k.to_s =~ /(uptime_seconds|timestamp|free)/ }.to_yaml %>"),
  }
}

class mcollective::agent::service {
  service { 'mcollective':
    ensure => $mcollective::enable_agent_service,
    enable => $mcollective::enable_agent_service,
  }
}

class mcollective::client {
  include mcollective::client::config
}

class mcollective::client::config {
  Ini_setting {
    path => "$mcollective::confdir/client.cfg",
  }

  ini_setting { "mcollective/client.cfg/connector":
    setting => 'connector',
    value   => 'rabbitmq',
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.vhost":
    setting => 'plugin.rabbitmq.vhost',
    value   => '/mcollective',
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.size":
    setting => 'plugin.rabbitmq.pool.size',
    value   => '1',
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.host":
    setting => 'plugin.rabbitmq.pool.1.host',
    value   => $mcollective::rabbit_host,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.port":
    setting => 'plugin.rabbitmq.pool.1.port',
    value   => $mcollective::rabbit_port,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.user":
    setting => 'plugin.rabbitmq.pool.1.user',
    value   => $mcollective::rabbit_user,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.password":
    setting => 'plugin.rabbitmq.pool.1.password',
    value   => $mcollective::rabbit_password,
  }

  $ssl_ensure = $mcollective::rabbit_ssl ? {
    true => present,
    default => absent,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.ssl":
    setting => 'plugin.rabbitmq.pool.1.ssl',
    value   => $mcollective::rabbit_ssl ? {
      true => '1',
      default => '0',
    },
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.ssl.ciphers":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.ciphers',
    value => $mcollective::rabbit_ssl_ciphers,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.ssl.ca":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.ca',
    value   => $mcollective::rabbit_ssl_cacert,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.ssl.cert":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.cert',
    value   => $mcollective::rabbit_ssl_cert,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.ssl.key":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.key',
    value   => $mcollective::rabbit_ssl_key,
  }

  ini_setting { "mcollective/client.cfg/plugin.rabbitmq.pool.1.ssl.fallback":
    ensure => $ssl_ensure,
    setting => 'plugin.rabbitmq.pool.1.ssl.fallback',
    value   => 0,
  }

  ini_setting { 'mcollective/client.cfg/plugin.psk':
    setting => 'plugin.psk',
    value => $mcollective::mcollective_pre_shared_key,
  }
}

class mcollective::puppet_agent {
  file { '/opt/puppetlabs/mcollective': ensure => directory}
  ->
  file { '/opt/puppetlabs/mcollective/plugins': ensure => directory}
  ->
  file { '/opt/puppetlabs/mcollective/plugins/mcollective': ensure => directory}

  file { '/opt/puppetlabs/mcollective/plugins/mcollective/agent':
    require => File['/opt/puppetlabs/mcollective/plugins/mcollective'],
    ensure => directory,
    source => 'puppet:///modules/mcollective/puppet_agent_repo/agent',
    purge => true,
    force => true,
    recurse => true,
  }

  file { '/opt/puppetlabs/mcollective/plugins/mcollective/aggregate':
    require => File['/opt/puppetlabs/mcollective/plugins/mcollective'],
    ensure => directory,
    source => 'puppet:///modules/mcollective/puppet_agent_repo/aggregate',
    purge => true,
    force => true,
    recurse => true,
  }

  file { '/opt/puppetlabs/mcollective/plugins/mcollective/application':
    require => File['/opt/puppetlabs/mcollective/plugins/mcollective'],
    ensure => directory,
    source => 'puppet:///modules/mcollective/puppet_agent_repo/application',
    purge => true,
    force => true,
    recurse => true,
  }

  file { '/opt/puppetlabs/mcollective/plugins/mcollective/data':
    require => File['/opt/puppetlabs/mcollective/plugins/mcollective'],
    ensure => directory,
    source => 'puppet:///modules/mcollective/puppet_agent_repo/data',
    purge => true,
    force => true,
    recurse => true,
  }

  file { '/opt/puppetlabs/mcollective/plugins/mcollective/util':
    require => File['/opt/puppetlabs/mcollective/plugins/mcollective'],
    ensure => directory,
    source => 'puppet:///modules/mcollective/puppet_agent_repo/util',
    purge => true,
    force => true,
    recurse => true,
  }

  file { '/opt/puppetlabs/mcollective/plugins/mcollective/validator':
    require => File['/opt/puppetlabs/mcollective/plugins/mcollective'],
    ensure => directory,
    source => 'puppet:///modules/mcollective/puppet_agent_repo/validator',
    purge => true,
    force => true,
    recurse => true,
  }
}


class mcollective::rabbit_vhost {
  rabbitmq_user { $mcollective::rabbit_user:
    admin    => false,
    password => $mcollective::rabbit_password,
  }

  rabbitmq_user { $mcollective::rabbit_admin_user:
    admin    => true,
    password => $mcollective::rabbit_admin_password,
  }

  rabbitmq_vhost { '/mcollective':
  }

  # collectivename_broadcast @ vhost
  rabbitmq_exchange { 'mcollective_broadcast@/mcollective': # main_collective
    user => $mcollective::rabbit_admin_user,
    password => $mcollective::rabbit_admin_password,
    type => 'topic',
  }

  rabbitmq_exchange { 'mcollective_directed@/mcollective':
    user => $mcollective::rabbit_admin_user,
    password => $mcollective::rabbit_admin_password,
    type => 'direct',
  }

  rabbitmq_user_permissions { "${mcollective::rabbit_user}@/mcollective":
    configure_permission => '.*',
    read_permission      => '.*',
    write_permission     => '.*',
  }

  rabbitmq_user_permissions { "${mcollective::rabbit_admin_user}@/mcollective":
    configure_permission => '.*',
    read_permission      => '.*',
    write_permission     => '.*',
  }
}
