// SERVER-7322
// @tags: [
//   requires_getmore,
// ]
import {add2dsphereVersionIfNeededForSpec} from "jstests/libs/query/geo_index_version_helpers.js";

let t = db.geo_exactfetch;
t.drop();

function test(indexname) {
    assert.eq(1, t.find({lon_lat: [-71.34895, 42.46037]}).itcount(), indexname);
    const spec = {lon_lat: indexname, population: -1};
    t.createIndex(spec, add2dsphereVersionIfNeededForSpec(spec));
    assert.eq(2, t.find({lon_lat: {$nearSphere: [-71.34895, 42.46037]}}).itcount(), indexname);
    assert.eq(1, t.find({lon_lat: [-71.34895, 42.46037]}).itcount(), indexname);
    t.dropIndex({lon_lat: indexname, population: -1});
}

t.insert({city: "B", lon_lat: [-71.34895, 42.46037], population: 1000});
t.insert({city: "A", lon_lat: [1.48736, 42.55327], population: 100});

test("2d");
test("2dsphere");
