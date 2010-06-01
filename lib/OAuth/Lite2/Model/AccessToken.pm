package OAuth::Lite2::Model::AccessToken;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    auth_id
    token
    expires_in
    secret
    secret_type
));

1;

