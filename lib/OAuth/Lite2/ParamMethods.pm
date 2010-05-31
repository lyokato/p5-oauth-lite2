package OAuth::Lite2::ParamMethods;

use strict;
use warnings;

use OAuth::Lite2::ParamMethod::AuthHeader;
use OAuth::Lite2::ParamMethod::FormEncodedBody;
use OAuth::Lite2::ParamMethod::URIQueryParameter;

use base 'Exporter';

our %EXPORT_TAGS = ( all => [qw/
    AUTH_HEADER FORM_BODY URI_QUERY
/] );

our @EXPORT_OK = map { @$_ } values %EXPORT_TAGS;

use constant AUTH_HEADER => 0;
use constant FORM_BODY   => 1;
use constant URI_QUERY   => 2;

my @METHODS = (
    OAuth::Lite2::ParamMethod::AuthHeader->new,
    OAuth::Lite2::ParamMethod::FormEncodedBody->new,
    OAuth::Lite2::ParamMethod::URIQueryParameter->new,
);

sub get_param_parser {
    my ($self, $req) = @_;
    for my $method ( @METHODS ) {
        return $method if $method->match($req)
    }
    return;
}

sub get_request_builder {
    my ($self, $type) = @_;
    return $METHODS[ $type ];
}

1;
