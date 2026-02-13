import time
from functools import wraps

from flask import jsonify, request, session

from app_context import cache


def rate_limit(max_per_minute=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            current_time = time.time()

            cache_copy = dict(cache)
            for key, timestamps in cache_copy.items():
                cache[key] = [t for t in timestamps if current_time - t < 60]
                if not cache[key]:
                    del cache[key]

            if ip in cache and len(cache[ip]) >= max_per_minute:
                return jsonify({"error": "Rate limit exceeded"}), 429

            cache.setdefault(ip, []).append(current_time)
            return f(*args, **kwargs)

        return wrapper

    return decorator


def get_authenticated_user_id():
    if not session.get("authenticated"):
        return None, (jsonify({"error": "Authentication required"}), 401)

    user_id = session.get("user_id")
    if not user_id:
        return None, (jsonify({"error": "No user ID found"}), 400)

    return user_id, None
