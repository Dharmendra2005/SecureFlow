const createSecurityHeaders = (req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-XSS-Protection", "0");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self' http: https:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none';",
  );
  next();
};

const createRequestLogger = (req, res, next) => {
  const startedAt = Date.now();

  res.on("finish", () => {
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - startedAt}ms`,
    );
  });

  next();
};

const createInMemoryRateLimiter = ({ windowMs, maxRequests }) => {
  const buckets = new Map();

  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:${req.path}`;
    const current = buckets.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > current.resetAt) {
      current.count = 0;
      current.resetAt = now + windowMs;
    }

    current.count += 1;
    buckets.set(key, current);

    if (current.count > maxRequests) {
      return res.status(429).json({
        message: "Too many requests. Please slow down and try again shortly.",
      });
    }

    res.setHeader("X-RateLimit-Limit", maxRequests);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, maxRequests - current.count));
    return next();
  };
};

module.exports = {
  createSecurityHeaders,
  createRequestLogger,
  createInMemoryRateLimiter,
};
