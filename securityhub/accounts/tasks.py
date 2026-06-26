from django.core.management import call_command


def flush_expired_tokens_task():
    call_command('flushexpiredtokens')
