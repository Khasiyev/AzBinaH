namespace Application.Dtos.AuthDtos;

public class LoginRequest
{
    /// <summary>///Email və ya UserName/// </summary>
    public string Login { get; set; } = null!;
    public string Password { get; set; } = null!;
}
