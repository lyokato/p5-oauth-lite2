package OAuth::Lite2::Model::AuthInfo;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    id
    user_id
    client_id
    scope
    refresh_token

    code
    redirect_uri
));

1;
