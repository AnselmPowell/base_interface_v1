/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.DJANGO_BASE_URL || 'https://basedatastorev1-production.up.railway.app'}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;