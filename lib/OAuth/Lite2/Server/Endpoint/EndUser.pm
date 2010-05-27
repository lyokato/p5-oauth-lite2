package OAuth::Lite2::Server::Endpoint::EndUser;

use strict;
use warnings;

use Params::Validate;

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {
        data_handler => {
            isa => 'OAuth::Lite2::Server::DataHandler'
        },
    });
    my $self = bless {
        data_handler => $args{data_handler},
    }, $class;
    return $self;
}

sub accept {

}

sub deny {

}

1;
