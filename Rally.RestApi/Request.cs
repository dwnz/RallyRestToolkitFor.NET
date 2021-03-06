﻿using Rally.RestApi.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace Rally.RestApi
{

  /// <summary>
  /// Represents a request to be sent to Rally
  /// </summary>
  [Serializable]
  public class Request
  {
    #region Constructor
    /// <summary>
    /// Create a new Request with the specified artifact type
    /// </summary>
    /// <param name="artifactName">The Rally artifact type being requested</param>
    /// <example>
    /// <code>
    /// Request request = new Request("PortfolioItem/Feature");
    /// </code>
    /// </example>
    public Request(string artifactName)
    {
      Configure(artifactName);
    }
    /// <summary>
    /// Create a new Request for the specified collection. (ie Defect.Tasks)
    /// The collection should have a _ref property.
    /// </summary>
    /// <param name="collection">The object containing the collection ref</param>
    /// <example>
    /// <code>
    /// DynamicJsonObject collection = new DynamicJsonObject();
    /// collection["_ref"] = "/hierarchicalrequirement/12345/defect.js";
    /// Request request = new Request(collection);
    /// </code>
    /// </example>
    public Request(DynamicJsonObject collection)
    {
      Configure(collection: collection);
    }
    /// <summary>
    /// Create a new empty Request.
    /// </summary>
    /// <example>
    /// <code>
    /// Request request = new Request();
    /// </code>
    /// </example>
    public Request()
    {
      Configure();
    }
    #endregion

    #region Configure
    private void Configure(string artifactName = null, DynamicJsonObject collection = null)
    {
      ArtifactName = artifactName;
      _collection = collection;
      Parameters = new Dictionary<string, dynamic>();
      Fetch = new List<string>();
      PageSize = MaxPageSize;
      Start = 1;
      Limit = PageSize;
    }
    #endregion

    #region Properties and Fields
    /// <summary>
    /// The maximum page size (200).
    /// </summary>
    public const int MaxPageSize = 200;

    internal Dictionary<string, dynamic> Parameters { get; private set; }

    private DynamicJsonObject _collection;
    /// <summary>
    /// An upper bound on the total results to be returned.
    /// </summary>
    public int Limit { get; set; }
    /// <summary>
    /// The name of the artifact that will be queried
    /// </summary>
    public string ArtifactName { get; set; }
    /// <summary>
    /// Page size for results. Must be between 1 and MAX_PAGE_SIZE, default is MAX_PAGE_SIZE. 
    /// </summary>
    public int PageSize { get; set; }
    /// <summary>
    /// A list of attributes to be returned in the result set.
    /// If null or empty true will be used.
    /// </summary>
    public List<string> Fetch { get; set; }
    /// <summary>
    /// Using ShallowFetch will only fetch the fields listed in the [] on the related items rather than fetching all fields on all objects.
    /// An example of the param is: shallowFetch=Name,WorkProduct[Name;FormattedID]
    /// The Fetch attributes will be treated as a shallow fetch if this is set to true.
    /// </summary>
    public bool UseShallowFetch { get; set; }
    /// <summary>
    /// A filter query to be applied to results before being returned
    /// </summary>
    public Query Query
    {
      get { return GetParameterValue("query"); }
      set { Parameters["query"] = value; }
    }
    /// <summary>
    /// Default is the user's default from Rally. In addition to the specified project, include projects above the specified one. 
    /// </summary>
    public bool? ProjectScopeUp
    {
      get { return GetParameterValue("projectScopeUp"); }
      set { Parameters["projectScopeUp"] = value; }
    }
    /// <summary>
    /// Default is the user's default from Rally. In addition to the specified project, include child projects below the specified one. 
    /// </summary>
    public bool? ProjectScopeDown
    {
      get { return GetParameterValue("projectScopeDown"); }
      set { Parameters["projectScopeDown"] = value; }
    }
    /// <summary>
    /// Start index (1-based) for queries. The default is 1. 
    /// </summary>
    public int Start
    {
      get { return GetParameterValue("start", 1); }
      set { Parameters["start"] = value; }
    }
    /// <summary>
    /// The ref for the workspace that you want the results from
    /// <example>
    /// /workspace/12345
    /// </example>
    /// </summary>
    public string Workspace
    {
      get { return GetParameterValue("workspace"); }
      set { Parameters["workspace"] = value; }
    }
    /// <summary>
    /// The ref for the project that you want the results from
    /// <example>
    /// /project/12345
    /// </example>
    /// </summary>
    public string Project
    {
      get { return GetParameterValue("project"); }
      set { Parameters["project"] = value; }
    }
    /// <summary>
    ///  A sort string. 
    ///  <example>ObjectId Desc</example>
    ///  <example>FormattedId</example>
    /// </summary>
    public string Order
    {
      get { return GetParameterValue("order"); }
      set { Parameters["order"] = value; }
    }
    #endregion

    #region Calculated Properties

    internal string Endpoint
    {
      get
      {
        if (!string.IsNullOrEmpty(ArtifactName))
        {
          switch (ArtifactName.ToLower())
          {
            case "user":
            case "subscription":
              return string.Format("/{0}s", ArtifactName.ToLower()); //special case for user/subscription endpoints
          }

          return string.Format("/{0}", ArtifactName.ToLower());
        }

        return Ref.GetRelativeRef(_collection["_ref"]);
      }
    }

    internal virtual string ShortRequestUrl { get { return String.Format("{0}{1}", Endpoint, ".js"); } }

    internal virtual string RequestUrl { get { return BuildQueryString(); } }

    #endregion

    #region AddParameter
    /// <summary>
    /// Ability to add parameters other than the ones explicitly exposed.
    /// </summary>
    /// <param name="key"></param>
    /// <param name="value"></param>
    /// <returns>true if added. false if the key already existed</returns>
    public bool AddParameter(string key, string value)
    {
      if (GetParameterValue(key) != null)
        return false;
      Parameters[key] = value;
      return true;
    }
    #endregion

    #region Helper: GetParameterValue
    private dynamic GetParameterValue(string keyValue, object defaultValue = null)
    {
      if (Parameters.ContainsKey(keyValue))
        return Parameters[keyValue];

      return defaultValue;
    }

    #endregion

    #region GetDataToSend
    internal Dictionary<string, string> GetDataToSend(bool urlEncodeData = false)
    {
      StringBuilder sb = new StringBuilder();
      Dictionary<string, string> data = new Dictionary<string, string>();
      int pageSize = Math.Min(Math.Min(MaxPageSize, PageSize), Limit);

      data.Add("pagesize", pageSize.ToString());

      if (Fetch.Count == 0)
        data.Add("fetch", "true");
      else
      {
        string keyword = "fetch";
        if (UseShallowFetch)
          keyword = "shallowFetch";

        bool first = true;
        sb.Clear();
        foreach (string currentFetch in Fetch)
        {
          if (first)
            first = false;
          else
            sb.Append(",");

          sb.Append(urlEncodeData ? HttpUtility.UrlEncode(currentFetch) : currentFetch);
        }

        data.Add(keyword, sb.ToString());
      }

      if (!Parameters.Keys.Contains("order"))
      {
        // Add order on 'ObjectID' clause to workaround server-side WSAPI bug
        data.Add("order", "ObjectID");
      }
      else
      {
        string orderString = Parameters["order"].ToString();
        List<string> orderList = orderString.Split(',').ToList();
        bool first = true;
        bool objectIdFound = false;
        sb.Clear();

        foreach (string currentOrder in orderList)
        {
          if (currentOrder.Contains("ObjectID") || currentOrder.Contains("ObjectID desc"))
          {
            objectIdFound = true;
          }

          if (first)
          {
            first = false;
          }
          else
          {
            sb.Append(",");
          }

          sb.Append(urlEncodeData ? HttpUtility.UrlEncode(currentOrder) : currentOrder);
        }

        if (!objectIdFound)
        {
          // Add 'ObjectID' to an existing order clause to workaround server-side WSAPI bug
          sb.Append(",ObjectID");
        }

        data.Add("order", sb.ToString());
      }

      foreach (string currentParameter in Parameters.Keys)
      {
        if (currentParameter.Equals("order", StringComparison.InvariantCultureIgnoreCase))
          continue;

        dynamic value = Parameters[currentParameter];
        if (value == null)
          continue;

        string dataValue;
        if (value is bool)
          dataValue = value.ToString().ToLower();
        else
          dataValue = value.ToString();

        data.Add(currentParameter, urlEncodeData ? HttpUtility.UrlEncode(dataValue) : dataValue);
      }

      return data;
    }
    #endregion

    #region BuildQueryString
    /// <summary>
    /// Create a query string from this request.
    /// </summary>
    /// <returns>A query string representation of this request</returns>
    private string BuildQueryString()
    {
      StringBuilder sb = new StringBuilder();
      sb.Append(ShortRequestUrl);

      Dictionary<string, string> data = GetDataToSend(true);
      bool isFirst = true;
      foreach (string key in data.Keys)
      {
        if (isFirst)
        {
          sb.Append("?");
          isFirst = false;
        }
        else
          sb.Append("&");

        sb.AppendFormat("{0}={1}", key, data[key]);
      }
      return sb.ToString();
    }
    #endregion

    #region CreateFromUrl
    /// <summary>
    /// Create a request object from a url string.
    /// </summary>
    /// <param name="url">the url we are creating from</param>
    /// <returns>A request object that represents the reference string.</returns>
    /// <example>
    /// <code>
    /// string url = "https://rally1.rallydev.com/slm/webservice/v2.0/hierarchicalrequirement/12345/defect.js?pagesize=172&amp;fetch=Name&amp;order=ObjectID&amp;start=57";
    /// Request request = Request.CreateFromUrl(url);
    /// </code>
    /// </example>
    public static Request CreateFromUrl(string url)
    {
      Request request = new Request();
      int index = url.IndexOf("?", StringComparison.Ordinal);

      string primaryUrl;

      if (index <= 0)
      {
        primaryUrl = url;
      }
      else
      {
        primaryUrl = url.Substring(0, index);
        string parameters = url.Substring(index + 1);
        string[] parameterParts = parameters.Split('&');
        foreach (string paramPart in parameterParts)
        {
          string[] paramParts = paramPart.Split('=');
          if (paramParts.Length != 2)
            continue;

          string valueString = HttpUtility.UrlDecode(paramParts[1]);
          if (paramParts[0].Equals("pagesize", StringComparison.InvariantCultureIgnoreCase))
          {
            int pageSize;
            if (Int32.TryParse(valueString, out pageSize))
              request.PageSize = pageSize;
          }
          else if (paramParts[0].Equals("start", StringComparison.InvariantCultureIgnoreCase))
          {
            int start;
            if (Int32.TryParse(valueString, out start))
              request.Start = start;
          }
          else if (paramParts[0].Equals("fetch", StringComparison.InvariantCultureIgnoreCase))
          {
            if (!valueString.Equals("true", StringComparison.InvariantCultureIgnoreCase))
            {
              string[] fetchParts = valueString.Split(new[] { "," }, StringSplitOptions.None);
              List<string> fetchString = new List<string>();
              fetchString.AddRange(fetchParts);
              request.Fetch = fetchString;
            }
          }
          else if (paramParts[0].Equals("order", StringComparison.InvariantCultureIgnoreCase))
          {
            request.Order = valueString;
          }
          else
          {
            if (request.Parameters.ContainsKey(paramParts[0]))
              request.Parameters[paramParts[0]] = valueString;
            else
              request.Parameters.Add(paramParts[0], valueString);
          }
        }
      }

      string primaryUrlStringToFind = "webservice/";
      primaryUrl = primaryUrl.Replace(".js", String.Empty);
      index = primaryUrl.IndexOf(primaryUrlStringToFind);
      string rightUrl = primaryUrl.Substring(index + primaryUrlStringToFind.Length + 1);
      index = rightUrl.IndexOf("/");
      string artifactUrl = rightUrl.Substring(index + 1);

      if (artifactUrl.Contains("/"))
      {
        DynamicJsonObject collection = new DynamicJsonObject();
        collection["_ref"] = primaryUrl;
        request._collection = collection;
      }
      else
        request.ArtifactName = artifactUrl;

      return request;
    }
    #endregion

    #region Clone
    /// <summary>
    /// Perform a deep clone of this request and all its parameters.
    /// </summary>
    /// <returns>The clone request</returns>
    /// <example>
    /// <code>
    /// Request request = new Request("Defect");
    /// request.Fetch = new List&lt;string&gt;() { "Name", "FormattedID" };
    /// 
    /// Request clonedRequest = request.Clone();
    /// </code>
    /// </example>
    public Request Clone()
    {
      Request request = _collection != null ? new Request(_collection) : new Request(ArtifactName);
      request.Limit = Limit;

      foreach (string dictionaryKey in Parameters.Keys)
      {
        request.Parameters[dictionaryKey] = Parameters[dictionaryKey];
      }

      request.Fetch = new List<string>(Fetch);

      return request;
    }
    #endregion
  }
}
