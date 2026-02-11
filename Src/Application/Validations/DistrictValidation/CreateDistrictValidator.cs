using Application.Abstracts.Repositories;
using Application.Dtos.DistrictDtos;
using FluentValidation;
using Microsoft.EntityFrameworkCore;
namespace Application.Validations.DistrictValidation;

public class CreateDistrictValidator : AbstractValidator<CreateDistrictRequest>
{
    public CreateDistrictValidator(IDistrictRepository districtRepository)
    {
        RuleFor(x => x.Name)
            .NotEmpty()
            .MaximumLength(100)
            .MustAsync(async (name, ct) =>
                !await districtRepository.ExistsByNameDistrictAsync(name, 0, ct))
            .WithMessage("This district name already exists.");

        RuleFor(x => x.CityId)
            .GreaterThan(0);
    }
}

