import { Test, TestingModule } from '@nestjs/testing';
import { MaisonEditionController } from './maison-edition.controller';
import { MaisonEditionService } from './maison-edition.service';

describe('MaisonEditionController', () => {
  let controller: MaisonEditionController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [MaisonEditionController],
      providers: [MaisonEditionService],
    }).compile();

    controller = module.get<MaisonEditionController>(MaisonEditionController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
