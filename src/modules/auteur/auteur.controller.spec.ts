import { Test, TestingModule } from '@nestjs/testing';
import { AuteurController } from './auteur.controller';
import { AuteurService } from './auteur.service';

describe('AuteurController', () => {
  let controller: AuteurController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuteurController],
      providers: [AuteurService],
    }).compile();

    controller = module.get<AuteurController>(AuteurController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
