use strict;
use warnings;

use Test::More tests => 31;

use OAuth::Lite2::Formatters;
use Try::Tiny;

my ($json, $xml, $form, $unknown);

TEST_FACTORY: {

    $json = OAuth::Lite2::Formatters->get_formatter_by_name("json");
    isa_ok($json, "OAuth::Lite2::Formatter::JSON");
    $json = OAuth::Lite2::Formatters->get_formatter_by_type("application/json");
    isa_ok($json, "OAuth::Lite2::Formatter::JSON");

    $xml = OAuth::Lite2::Formatters->get_formatter_by_name("xml");
    isa_ok($xml, "OAuth::Lite2::Formatter::XML");
    $xml = OAuth::Lite2::Formatters->get_formatter_by_type("application/xml");
    isa_ok($xml, "OAuth::Lite2::Formatter::XML");

    $form = OAuth::Lite2::Formatters->get_formatter_by_name("form");
    isa_ok($form, "OAuth::Lite2::Formatter::FormURLEncoded");
    $form = OAuth::Lite2::Formatters->get_formatter_by_type("application/x-www-form-urlencoded");
    isa_ok($form, "OAuth::Lite2::Formatter::FormURLEncoded");

    $unknown = OAuth::Lite2::Formatters->get_formatter_by_name("unknown");
    ok(!$unknown);
    $unknown = OAuth::Lite2::Formatters->get_formatter_by_type("unknown");
    ok(!$unknown);
};

my $params1 = {
    access_token        => q{foo},
    refresh_token       => q{bar},
    access_token_secret => q{buz},
    expires_in          => 3600,
};

TEST_JSON: {
    is($json->name, "json");
    is($json->type, "application/json");
    is($json->format($params1), '{"expires_in":3600,"refresh_token":"bar","access_token_secret":"buz","access_token":"foo"}');

    my $parsed = $json->parse('{"expires_in":3600,"refresh_token":"bar","access_token_secret":"buz","access_token":"foo"}');

    is($parsed->{access_token}, q{foo});
    is($parsed->{refresh_token}, q{bar});
    is($parsed->{access_token_secret}, q{buz});
    is($parsed->{expires_in}, 3600);

    my $message;
    try {
        $json->parse("invalid format");
    } catch {
        $message = $_->message;
    };
    like($message, qr/^Parse Error:/);
};

TEST_XML: {
    is($xml->name, "xml");
    is($xml->type, "application/xml");
    is($xml->format($params1), '<?xml version="1.0" encoding="UTF-8"?><OAuth><expires_in>3600</expires_in><refresh_token>bar</refresh_token><access_token_secret>buz</access_token_secret><access_token>foo</access_token></OAuth>');

    my $parsed = $xml->parse('<?xml version="1.0" encoding="UTF-8"?><OAuth><expires_in>3600</expires_in><refresh_token>bar</refresh_token><access_token_secret>buz</access_token_secret><access_token>foo</access_token></OAuth>');

    is($parsed->{access_token}, q{foo});
    is($parsed->{refresh_token}, q{bar});
    is($parsed->{access_token_secret}, q{buz});
    is($parsed->{expires_in}, 3600);

    my $message;
    try {
        $xml->parse("invalid format");
    } catch {
        $message = $_->message;
    };
    like($message, qr/^Parse Error:/);
};

TEST_FORM: {
    is($form->name, "form");
    is($form->type, "application/x-www-form-urlencoded");
    is($form->format($params1), 'access_token=foo&access_token_secret=buz&expires_in=3600&refresh_token=bar');

    my $parsed = $form->parse('access_token=foo&access_token_secret=buz&expires_in=3600&refresh_token=bar');

    is($parsed->{access_token}, q{foo});
    is($parsed->{refresh_token}, q{bar});
    is($parsed->{access_token_secret}, q{buz});
    is($parsed->{expires_in}, 3600);
};

# TODO invalid format test
