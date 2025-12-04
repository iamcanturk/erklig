# Test Environment for ERKLIG
# This creates a vulnerable web server with planted malware for testing

FROM php:8.2-apache

# Set working directory
WORKDIR /var/www/html

# Create directory structure simulating a real WordPress site
RUN mkdir -p wp-content/uploads/2024 \
    && mkdir -p wp-content/themes/theme1 \
    && mkdir -p wp-content/plugins/plugin1 \
    && mkdir -p wp-includes \
    && mkdir -p images \
    && mkdir -p tmp

# Copy test malware files
COPY testbed/ /var/www/html/

# Set permissions (some intentionally dangerous for testing)
RUN chmod 777 /var/www/html/wp-content/uploads/2024 \
    && chmod 666 /var/www/html/tmp/config.php

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost/ || exit 1
