use strict;
use warnings;

use Test::More tests => 11;

use OAuth::Lite2::Util qw(
    encode_param
    decode_param
    parse_content
    build_content
);

use Hash::MultiValue;

TEST_ENCODE: {

my $param = q{123 @#$%&hoge hoge+._-~};
my $encoded = encode_param($param);
is($encoded, q{123%20%40%23%24%25%26hoge%20hoge%2B._-~});
my $decoded = decode_param($encoded);
is($decoded, $param);

};

TEST_PARSE_CONTENT: {
    my $content = q{aaa=bbb&bbb=ccc&ddd=eee&aaa=ddd};
    my $params  = parse_content($content);
    is($params->{bbb}, 'ccc');
    is($params->get('bbb'), 'ccc');
    ok(!$params->get('fff'));
    is($params->get('aaa'), 'ddd');
    my @aaa = $params->get_all('aaa');
    is(scalar @aaa, 2);
    is($aaa[0], 'bbb');
    is($aaa[1], 'ddd');
};

TEST_BUILD_CONTENT: {
    my $params = {
        aaa => 'bbb',
        bbb => 'ccc',
        ccc => 'ddd',
        ddd => ['eee', 'fff'],
    };
    my $content = build_content($params);
    is($content, 'aaa=bbb&bbb=ccc&ccc=ddd&ddd=eee&ddd=fff');
    $params = Hash::MultiValue->new(
        aaa => 'bbb',
        bbb => 'ccc',
        ccc => 'ddd',
        ddd => 'eee',
        ddd => 'fff',
    );
    $content = build_content($params);
    is($content, 'aaa=bbb&bbb=ccc&ccc=ddd&ddd=eee&ddd=fff');
};
