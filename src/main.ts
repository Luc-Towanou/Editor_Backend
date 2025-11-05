import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

import fastifyCors from '@fastify/cors';
import fastifyCompress from '@fastify/compress';

import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

import { fastifyCookie } from '@fastify/cookie'; // package name fastify-cookie
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { PrismaClient } from '@prisma/client';

async function bootstrap() {
   const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
    { bufferLogs: true },
  );

  // const app = await NestFactory.create(AppModule, { bufferLogs: true });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // ignore les champs inconnus
      transform: true, // convertit les types automatiquement
    }),
  );
  app.setGlobalPrefix('api'); // toutes tes routes commenceront par /api
  // --- Swagger Configuration  ---
  const config = new DocumentBuilder()
    .setTitle('Editor API') // Nom de ton API
    .setDescription('Documentation interactive de l’API Editor 📖')
    .setVersion('1.0')
    .addTag('events') // Exemple de tag
    .addBearerAuth() // Si tu veux gérer l’authentification par token JWT
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('docs', app, document, {
    customSiteTitle: 'Editor API Docs',
    explorer: true,
  });// --- Fin configuration Swagger ---



  await app.register(fastifyCors, {
    origin: '*', // temporairement, pour le dev
  });

  await app.register(
    fastifyCompress, { global: true }
  );
  // register cookie plugin
  await app.register(fastifyCookie, {
    secret: process.env.COOKIE_SECRET || 'change_me', // optional for signed cookies
  });
  //Si tu rencontres une erreur du type CSP blocked, ajoute ceci :
  //   app.register(helmet, {
  //   contentSecurityPolicy: false,
  // });

  app.enableShutdownHooks(); // ← important
  const prisma = new PrismaClient();

  process.on('SIGINT', async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
  
  // const app = await NestFactory.create(AppModule);
  const port = Number(process.env.PORT) || 3000;
  // await app.listen(process.env.PORT ?? 3000);
  await app.listen(port, '0.0.0.0');
  console.log(`🚀 Server running on ${port}`);
}
bootstrap();
