package OAuth::Lite2::Server::Flows;

use strict;
use warnings;

use OAuth::Lite2::Server::Flow::WebServer;
use OAuth::Lite2::Server::Flow::UserAgent;
use OAuth::Lite2::Server::Flow::Device;
use OAuth::Lite2::Server::Flow::UsernameAndPassword;
use OAuth::Lite2::Server::Flow::ClientCredentials;

my %FLOWS;

sub _add_flow {
    my ($class, $flow) = @_;
    $FLOWS{$flow->name} = $flow;
}

__PACKAGE__->_add_flow( OAuth::Lite2::Server::Flow::WebServer->new );
__PACKAGE__->_add_flow( OAuth::Lite2::Server::Flow::UserAgent->new );
__PACKAGE__->_add_flow( OAuth::Lite2::Server::Flow::Device->new );
__PACKAGE__->_add_flow( OAuth::Lite2::Server::Flow::UsernameAndPassword->new );
__PACKAGE__->_add_flow( OAuth::Lite2::Server::Flow::ClientCredentials->new );

sub get_flow {
    my ($class, $flow_name) = @_;
    return $FLOWS{$flow_name};
}

1;
