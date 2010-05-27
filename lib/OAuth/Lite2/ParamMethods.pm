package OAuth::Lite2::ParamMethods;

use strict;
use warnings;

use OAuth::Lite2::ParamMethod::AuthHeader;
use OAuth::Lite2::ParamMethod::FormEncodedBody;
use OAuth::Lite2::ParamMethod::URIQueryParameter;

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

1;
