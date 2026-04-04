# SecureFlow

Phase 0 foundation for a DevSecOps security platform with:

- React frontend for dashboards and platform controls
- Node.js and Express backend for APIs and orchestration
- MongoDB for repositories, scan jobs, and vulnerability reports
- Redis and BullMQ for asynchronous scan processing
- GitHub repository intake with local cloning for scan preparation

## Project structure

- `Frontend/` React + Vite dashboard
- `Backend/` Express API, MongoDB models, Redis queue, and worker
- `Backend/workspace/repos/` local repository clone workspace
- `docker-compose.yml` MongoDB and Redis service definitions

## Local setup

1. Copy `Backend/.env.example` to `Backend/.env`
2. Copy `Frontend/.env.example` to `Frontend/.env`
3. Copy `.env.example` to `.env`
4. Start infrastructure with `docker compose up -d`
5. Start backend with `npm install` then `npm run dev` inside `Backend`
6. Start frontend with `npm install` then `npm run dev` inside `Frontend`

The default local ports are `5050` for the backend API, `27018` for MongoDB, and `6380` for Redis to avoid common local port conflicts.

## API endpoints

- `GET /api/health` infrastructure health and queue metrics
- `GET /api/dashboard` dashboard snapshot for the frontend
- `POST /api/scans` enqueue a sample scan job
