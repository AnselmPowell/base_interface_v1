export const DJANGO_BASE_URL=process.env.DJANGO_BASE_URL
export const DJANGO_API_ENDPOINT=`${DJANGO_BASE_URL}/api/`
export const DJANGO_API_ENDPOINT_LOCAL = 'http://localhost:8001/api/' || 'http://127.0.0.1:8001/api/'