using Application.Abstracts.Repositories;
using Application.Dtos.CityDtos;
using FluentValidation;

namespace Application.Validations.CityValidation;

public class UpdateCityValidator:AbstractValidator<UpdateCityRequest>
{
    public UpdateCityValidator(ICityRepository cityRepository)
    {
        RuleFor(x => x.Name)
            .NotEmpty().WithMessage("City name cannot be empty.")
            .MaximumLength(100).WithMessage("City name can be at most 100 characters long.")
             .MustAsync(async (request, name, ct) =>
                !await cityRepository.ExistsByNameAsync(name, request.Id, ct)
            )
            .WithMessage("This city name already exists.");
    }
}
