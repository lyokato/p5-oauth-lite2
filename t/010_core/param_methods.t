use strict;
use warnings;

use Test::More tests => 4;

use OAuth::Lite2::ParamMethods qw(AUTH_HEADER FORM_BODY URI_QUERY);


my ($auth, $body, $query, $unknown);

TEST_FACTORY: {

    $auth = OAuth::Lite2::ParamMethods->get_request_builder(AUTH_HEADER);
    isa_ok($auth, "OAuth::Lite2::ParamMethod::AuthHeader");

    $body = OAuth::Lite2::ParamMethods->get_request_builder(FORM_BODY);
    isa_ok($body, "OAuth::Lite2::ParamMethod::FormEncodedBody");

    $query = OAuth::Lite2::ParamMethods->get_request_builder(URI_QUERY);
    isa_ok($query, "OAuth::Lite2::ParamMethod::URIQueryParameter");

    $unknown = OAuth::Lite2::ParamMethods->get_request_builder(10);
    ok(!$unknown);

    # TODO TEST get_param_parser($req)
};


#TEST_AUTH_HEADER: {
#    # my $req = $auth->build_request();
#};
#
#TEST_FORM_BODY: {
#    #my $req = $body->build_request();
#};
#
#TEST_URI_QUERY: {
#    #my $req = $query->build_request();
#};
