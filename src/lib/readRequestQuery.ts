/**
 * readRequestBody reads in the incoming request body
 * Use await readRequestBody(..) in an async function to get the string
 * @param {Request} request the incoming request to read from
 */
export default async (request: Request, key: string | void): Promise<any> => {
  const query = {};
  const searchParams = (new URL(request.clone().url)).searchParams;
  if (key) {
    return searchParams.get(key);
  }

  searchParams.forEach((varValue, varName) => {
    if (typeof query[varName] !== 'undefined' && varName.includes(`[`) && varName.includes(`]`)) {
      const key = varName.split(`[`)[1].replace(`]`, ``);
      if (key === ``) {
        query[varName].push(varValue);
      }
      if (typeof query[varName][key] === 'undefined') {
        let _varName = varName.split(`[`)[0];
        query[_varName][key] = [];
      }
      query[varName][key].push(varValue);
    } else {
      query[varName] = varValue;
    }
  });
  return query;
};
