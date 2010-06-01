package OAuth::Lite2::Server::Flow::UserAgent;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Flow';

sub name { 'user_agent' }

sub new {
    my $class = shift;
    bless {
        token_endpoint_actions => { },
    }, $class;
}

1;

