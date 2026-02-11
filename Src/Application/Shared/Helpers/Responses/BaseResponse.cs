namespace Application.Shared.Helpers.Responses;

public class BaseResponse<T>
{
    public string Message { get; set; }
    public bool Success { get; set; }
    public T? Data { get; set; }
    public List<string>? Errors { get; set; }

    public static BaseResponse<T> Ok(T? data, string? message = "Success")
    {
        return new BaseResponse<T>
        {
            Success = true,
            Message = message,
            Data = data
        };
    }

    public static BaseResponse<T> Fail( string? message = "Failure")
    {
        return new BaseResponse<T>
        {
            Success = false,
            Message = message
          
        };
    }
    public static BaseResponse<T> Fail(string message, List<string> errors)
       => new BaseResponse<T>
       {
           Success = false,
           Message = message,
           Errors = errors
       };
}
public class BaseResponse
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public List<string>? Errors { get; set; }

    public static BaseResponse Ok(string? message = "Success")
    {
        return new BaseResponse
        {
            Success = true,
            Message = message
        };
    }

    public static BaseResponse Fail(string message = "Failure")
        => new BaseResponse
        {
            Success = false,
            Message = message
        };

    public static BaseResponse Fail(string message, List<string> errors)
        => new BaseResponse
        {
            Success = false,
            Message = message,
            Errors = errors
        };

}